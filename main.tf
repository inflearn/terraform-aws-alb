locals {
  create_lb = var.create_lb && var.putin_khuylo
}

resource "aws_lb" "this" {
  count = local.create_lb ? 1 : 0

  name        = var.name
  name_prefix = var.name_prefix

  load_balancer_type = var.load_balancer_type
  internal           = var.internal
  security_groups    = var.security_groups
  subnets            = var.subnets

  idle_timeout                     = var.idle_timeout
  enable_cross_zone_load_balancing = var.enable_cross_zone_load_balancing
  enable_deletion_protection       = var.enable_deletion_protection
  enable_http2                     = var.enable_http2
  ip_address_type                  = var.ip_address_type
  drop_invalid_header_fields       = var.drop_invalid_header_fields
  enable_waf_fail_open             = var.enable_waf_fail_open
  desync_mitigation_mode           = var.desync_mitigation_mode

  dynamic "access_logs" {
    for_each = length(keys(var.access_logs)) == 0 ? [] : [var.access_logs]

    content {
      enabled = try(access_logs.value.enabled, try(access_logs.value.bucket, null) != null)
      bucket  = try(access_logs.value.bucket, null)
      prefix  = try(access_logs.value.prefix, null)
    }
  }

  dynamic "subnet_mapping" {
    for_each = var.subnet_mapping

    content {
      subnet_id            = subnet_mapping.value.subnet_id
      allocation_id        = try(subnet_mapping.value.allocation_id, null)
      private_ipv4_address = try(subnet_mapping.value.private_ipv4_address, null)
      ipv6_address         = try(subnet_mapping.value.ipv6_address, null)
    }
  }

  tags = merge(
    var.tags,
    var.lb_tags,
    {
      Name = var.name != null ? var.name : var.name_prefix
    },
  )

  timeouts {
    create = var.load_balancer_create_timeout
    update = var.load_balancer_update_timeout
    delete = var.load_balancer_delete_timeout
  }
}

resource "aws_lb_target_group" "main" {
  count = local.create_lb ? length(var.target_groups) : 0

  name        = try(var.target_groups[count.index].name, null)
  name_prefix = try(var.target_groups[count.index].name_prefix, null)

  vpc_id           = var.vpc_id
  port             = try(var.target_groups[count.index].backend_port, null)
  protocol         = try(var.target_groups[count.index].backend_protocol, null) != null ? upper(try(var.target_groups[count.index].backend_protocol)) : null
  protocol_version = try(var.target_groups[count.index].protocol_version, null) != null ? upper(try(var.target_groups[count.index].protocol_version)) : null
  target_type      = try(var.target_groups[count.index].target_type, null)

  deregistration_delay               = try(var.target_groups[count.index].deregistration_delay, null)
  slow_start                         = try(var.target_groups[count.index].slow_start, null)
  proxy_protocol_v2                  = try(var.target_groups[count.index].proxy_protocol_v2, false)
  lambda_multi_value_headers_enabled = try(var.target_groups[count.index].lambda_multi_value_headers_enabled, false)
  load_balancing_algorithm_type      = try(var.target_groups[count.index].load_balancing_algorithm_type, null)
  preserve_client_ip                 = try(var.target_groups[count.index].preserve_client_ip, null)

  dynamic "health_check" {
    for_each = length(keys(try(var.target_groups[count.index].health_check, {}))) == 0 ? [] : [try(var.target_groups[count.index].health_check, {})]

    content {
      enabled             = try(health_check.value.enabled, null)
      interval            = try(health_check.value.interval, null)
      path                = try(health_check.value.path, null)
      port                = try(health_check.value.port, null)
      healthy_threshold   = try(health_check.value.healthy_threshold, null)
      unhealthy_threshold = try(health_check.value.unhealthy_threshold, null)
      timeout             = try(health_check.value.timeout, null)
      protocol            = try(health_check.value.protocol, null)
      matcher             = try(health_check.value.matcher, null)
    }
  }

  dynamic "stickiness" {
    for_each = length(keys(try(var.target_groups[count.index].stickiness, {}))) == 0 ? [] : [try(var.target_groups[count.index].stickiness, {})]

    content {
      enabled         = try(stickiness.value.enabled, null)
      cookie_duration = try(stickiness.value.cookie_duration, null)
      type            = try(stickiness.value.type, null)
    }
  }

  tags = merge(
    var.tags,
    var.target_group_tags,
    try(var.target_groups[count.index].tags, {}),
    {
      "Name" = try(var.target_groups[count.index].name, try(var.target_groups[count.index].name_prefix, ""))
    },
  )

  lifecycle {
    create_before_destroy = true
  }
}

locals {
  # Merge the target group index into a product map of the targets so we
  # can figure out what target group we should attach each target to.
  # Target indexes can be dynamically defined, but need to match
  # the function argument reference. This means any additional arguments
  # can be added later and only need to be updated in the attachment resource below.
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group_attachment#argument-reference
  target_group_attachments = merge(flatten([
    for index, group in var.target_groups : [
      for k, targets in group : {
        for target_key, target in targets : join(".", [index, target_key]) => merge({ tg_index = index }, target)
      }
      if k == "targets"
    ]
  ])...)
}

resource "aws_lb_target_group_attachment" "this" {
  for_each = local.create_lb && local.target_group_attachments != null ? local.target_group_attachments : {}

  target_group_arn  = aws_lb_target_group.main[each.value.tg_index].arn
  target_id         = each.value.target_id
  port              = try(each.value.port, null)
  availability_zone = try(each.value.availability_zone, null)
}

resource "aws_lb_listener_rule" "https_listener_rule" {
  count = local.create_lb ? length(var.https_listener_rules) : 0

  listener_arn = aws_lb_listener.frontend_https[try(var.https_listener_rules[count.index].https_listener_index, count.index)].arn
  priority     = try(var.https_listener_rules[count.index].priority, null)

  # authenticate-cognito actions
  dynamic "action" {
    for_each = [
      for action_rule in var.https_listener_rules[count.index].actions :
      action_rule
      if action_rule.type == "authenticate-cognito"
    ]

    content {
      type = action.value["type"]
      authenticate_cognito {
        authentication_request_extra_params = try(action.value.authentication_request_extra_params, null)
        on_unauthenticated_request          = try(action.value.on_authenticated_request, null)
        scope                               = try(action.value.scope, null)
        session_cookie_name                 = try(action.value.session_cookie_name, null)
        session_timeout                     = try(action.value.session_timeout, null)
        user_pool_arn                       = action.value["user_pool_arn"]
        user_pool_client_id                 = action.value["user_pool_client_id"]
        user_pool_domain                    = action.value["user_pool_domain"]
      }
    }
  }

  # authenticate-oidc actions
  dynamic "action" {
    for_each = [
      for action_rule in var.https_listener_rules[count.index].actions :
      action_rule
      if action_rule.type == "authenticate-oidc"
    ]

    content {
      type = action.value["type"]
      authenticate_oidc {
        # Max 10 extra params
        authentication_request_extra_params = try(action.value.authentication_request_extra_params, null)
        authorization_endpoint              = action.value["authorization_endpoint"]
        client_id                           = action.value["client_id"]
        client_secret                       = action.value["client_secret"]
        issuer                              = action.value["issuer"]
        on_unauthenticated_request          = try(action.value.on_unauthenticated_request, null)
        scope                               = try(action.value.scope, null)
        session_cookie_name                 = try(action.value.session_cookie_name, null)
        session_timeout                     = try(action.value.session_timeout, null)
        token_endpoint                      = action.value["token_endpoint"]
        user_info_endpoint                  = action.value["user_info_endpoint"]
      }
    }
  }

  # redirect actions
  dynamic "action" {
    for_each = [
      for action_rule in var.https_listener_rules[count.index].actions :
      action_rule
      if action_rule.type == "redirect"
    ]

    content {
      type = action.value["type"]
      redirect {
        host        = try(action.value.host, null)
        path        = try(action.value.path, null)
        port        = try(action.value.port, null)
        protocol    = try(action.value.protocol, null)
        query       = try(action.value.query, null)
        status_code = action.value["status_code"]
      }
    }
  }

  # fixed-response actions
  dynamic "action" {
    for_each = [
      for action_rule in var.https_listener_rules[count.index].actions :
      action_rule
      if action_rule.type == "fixed-response"
    ]

    content {
      type = action.value["type"]
      fixed_response {
        message_body = try(action.value.message_body, null)
        status_code  = try(action.value.status_code, null)
        content_type = action.value["content_type"]
      }
    }
  }

  # forward actions
  dynamic "action" {
    for_each = [
      for action_rule in var.https_listener_rules[count.index].actions :
      action_rule
      if action_rule.type == "forward"
    ]

    content {
      type             = action.value["type"]
      target_group_arn = aws_lb_target_group.main[try(action.value.target_group_index, count.index)].id
    }
  }

  # weighted forward actions
  dynamic "action" {
    for_each = [
      for action_rule in var.https_listener_rules[count.index].actions :
      action_rule
      if action_rule.type == "weighted-forward"
    ]

    content {
      type = "forward"
      forward {
        dynamic "target_group" {
          for_each = action.value["target_groups"]

          content {
            arn    = aws_lb_target_group.main[target_group.value["target_group_index"]].id
            weight = target_group.value["weight"]
          }
        }
        dynamic "stickiness" {
          for_each = [try(action.value.stickiness, {})]

          content {
            enabled  = try(stickiness.value["enabled"], false)
            duration = try(stickiness.value["duration"], 1)
          }
        }
      }
    }
  }

  # Path Pattern condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.https_listener_rules[count.index].conditions :
      condition_rule
      if length(try(condition_rule.path_patterns, [])) > 0
    ]

    content {
      path_pattern {
        values = condition.value["path_patterns"]
      }
    }
  }

  # Host header condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.https_listener_rules[count.index].conditions :
      condition_rule
      if length(try(condition_rule.host_headers, [])) > 0
    ]

    content {
      host_header {
        values = condition.value["host_headers"]
      }
    }
  }

  # Http header condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.https_listener_rules[count.index].conditions :
      condition_rule
      if length(try(condition_rule.http_headers, [])) > 0
    ]

    content {
      dynamic "http_header" {
        for_each = condition.value["http_headers"]

        content {
          http_header_name = http_header.value["http_header_name"]
          values           = http_header.value["values"]
        }
      }
    }
  }

  # Http request method condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.https_listener_rules[count.index].conditions :
      condition_rule
      if length(try(condition_rule.http_request_methods, [])) > 0
    ]

    content {
      http_request_method {
        values = condition.value["http_request_methods"]
      }
    }
  }

  # Query string condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.https_listener_rules[count.index].conditions :
      condition_rule
      if length(try(condition_rule.query_strings, [])) > 0
    ]

    content {
      dynamic "query_string" {
        for_each = condition.value["query_strings"]

        content {
          key   = try(query_string.value.key, null)
          value = query_string.value["value"]
        }
      }
    }
  }

  # Source IP address condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.https_listener_rules[count.index].conditions :
      condition_rule
      if length(try(condition_rule.source_ips, [])) > 0
    ]

    content {
      source_ip {
        values = condition.value["source_ips"]
      }
    }
  }

  tags = merge(
    var.tags,
    var.https_listener_rules_tags,
    try(var.https_listener_rules[count.index].tags, {}),
  )
}

resource "aws_lb_listener_rule" "http_tcp_listener_rule" {
  count = local.create_lb ? length(var.http_tcp_listener_rules) : 0

  listener_arn = aws_lb_listener.frontend_http_tcp[try(var.http_tcp_listener_rules[count.index].http_tcp_listener_index, count.index)].arn
  priority     = try(var.http_tcp_listener_rules[count.index].priority, null)

  # redirect actions
  dynamic "action" {
    for_each = [
      for action_rule in var.http_tcp_listener_rules[count.index].actions :
      action_rule
      if action_rule.type == "redirect"
    ]

    content {
      type = action.value["type"]
      redirect {
        host        = try(action.value.host, null)
        path        = try(action.value.path, null)
        port        = try(action.value.port, null)
        protocol    = try(action.value.protocol, null)
        query       = try(action.value.query, null)
        status_code = action.value["status_code"]
      }
    }
  }

  # fixed-response actions
  dynamic "action" {
    for_each = [
      for action_rule in var.http_tcp_listener_rules[count.index].actions :
      action_rule
      if action_rule.type == "fixed-response"
    ]

    content {
      type = action.value["type"]
      fixed_response {
        message_body = try(action.value.message_body, null)
        status_code  = try(action.value.status_code, null)
        content_type = action.value["content_type"]
      }
    }
  }

  # forward actions
  dynamic "action" {
    for_each = [
      for action_rule in var.http_tcp_listener_rules[count.index].actions :
      action_rule
      if action_rule.type == "forward"
    ]

    content {
      type             = action.value["type"]
      target_group_arn = aws_lb_target_group.main[try(action.value.target_group_index, count.index)].id
    }
  }

  # weighted forward actions
  dynamic "action" {
    for_each = [
      for action_rule in var.http_tcp_listener_rules[count.index].actions :
      action_rule
      if action_rule.type == "weighted-forward"
    ]

    content {
      type = "forward"
      forward {
        dynamic "target_group" {
          for_each = action.value["target_groups"]

          content {
            arn    = aws_lb_target_group.main[target_group.value["target_group_index"]].id
            weight = target_group.value["weight"]
          }
        }
        dynamic "stickiness" {
          for_each = [try(action.value.stickiness, {})]

          content {
            enabled  = try(stickiness.value["enabled"], false)
            duration = try(stickiness.value["duration"], 1)
          }
        }
      }
    }
  }

  # Path Pattern condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.http_tcp_listener_rules[count.index].conditions :
      condition_rule
      if length(try(condition_rule.path_patterns, [])) > 0
    ]

    content {
      path_pattern {
        values = condition.value["path_patterns"]
      }
    }
  }

  # Host header condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.http_tcp_listener_rules[count.index].conditions :
      condition_rule
      if length(try(condition_rule.host_headers, [])) > 0
    ]

    content {
      host_header {
        values = condition.value["host_headers"]
      }
    }
  }

  # Http header condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.http_tcp_listener_rules[count.index].conditions :
      condition_rule
      if length(try(condition_rule.http_headers, [])) > 0
    ]

    content {
      dynamic "http_header" {
        for_each = condition.value["http_headers"]

        content {
          http_header_name = http_header.value["http_header_name"]
          values           = http_header.value["values"]
        }
      }
    }
  }

  # Http request method condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.http_tcp_listener_rules[count.index].conditions :
      condition_rule
      if length(try(condition_rule.http_request_methods, [])) > 0
    ]

    content {
      http_request_method {
        values = condition.value["http_request_methods"]
      }
    }
  }

  # Query string condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.http_tcp_listener_rules[count.index].conditions :
      condition_rule
      if length(try(condition_rule.query_strings, [])) > 0
    ]

    content {
      dynamic "query_string" {
        for_each = condition.value["query_strings"]

        content {
          key   = try(query_string.value.key, null)
          value = query_string.value["value"]
        }
      }
    }
  }

  # Source IP address condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.http_tcp_listener_rules[count.index].conditions :
      condition_rule
      if length(try(condition_rule.source_ips, [])) > 0
    ]

    content {
      source_ip {
        values = condition.value["source_ips"]
      }
    }
  }

  tags = merge(
    var.tags,
    var.http_tcp_listener_rules_tags,
    try(var.http_tcp_listener_rules[count.index].tags, {}),
  )
}

resource "aws_lb_listener" "frontend_http_tcp" {
  count = local.create_lb ? length(var.http_tcp_listeners) : 0

  load_balancer_arn = aws_lb.this[0].arn

  port     = var.http_tcp_listeners[count.index]["port"]
  protocol = var.http_tcp_listeners[count.index]["protocol"]

  dynamic "default_action" {
    for_each = length(keys(var.http_tcp_listeners[count.index])) == 0 ? [] : [var.http_tcp_listeners[count.index]]

    # Defaults to forward action if action_type not specified
    content {
      type             = try(default_action.value.action_type, "forward")
      target_group_arn = contains([null, "", "forward"], try(default_action.value.action_type, "")) ? aws_lb_target_group.main[try(default_action.value.target_group_index, count.index)].id : null

      dynamic "redirect" {
        for_each = length(keys(try(default_action.value.redirect, {}))) == 0 ? [] : [try(default_action.value.redirect, {})]

        content {
          path        = try(redirect.value.path, null)
          host        = try(redirect.value.host, null)
          port        = try(redirect.value.port, null)
          protocol    = try(redirect.value.protocol, null)
          query       = try(redirect.value.query, null)
          status_code = redirect.value["status_code"]
        }
      }

      dynamic "fixed_response" {
        for_each = length(keys(try(default_action.value.fixed_response, {}))) == 0 ? [] : [try(default_action.value.fixed_response, {})]

        content {
          content_type = fixed_response.value["content_type"]
          message_body = try(fixed_response.value.message_body, null)
          status_code  = try(fixed_response.value.status_code, null)
        }
      }
    }
  }

  tags = merge(
    var.tags,
    var.http_tcp_listeners_tags,
    try(var.http_tcp_listeners[count.index].tags, {}),
  )
}

resource "aws_lb_listener" "frontend_https" {
  count = local.create_lb ? length(var.https_listeners) : 0

  load_balancer_arn = aws_lb.this[0].arn

  port            = var.https_listeners[count.index]["port"]
  protocol        = try(var.https_listeners[count.index].protocol, "HTTPS")
  certificate_arn = var.https_listeners[count.index]["certificate_arn"]
  ssl_policy      = try(var.https_listeners[count.index].ssl_policy, var.listener_ssl_policy_default)
  alpn_policy     = try(var.https_listeners[count.index].alpn_policy, null)

  dynamic "default_action" {
    for_each = length(keys(var.https_listeners[count.index])) == 0 ? [] : [var.https_listeners[count.index]]

    # Defaults to forward action if action_type not specified
    content {
      type             = try(default_action.value.action_type, "forward")
      target_group_arn = contains([null, "", "forward"], try(default_action.value.action_type, "")) ? aws_lb_target_group.main[try(default_action.value.target_group_index, count.index)].id : null

      dynamic "redirect" {
        for_each = length(keys(try(default_action.value.redirect, {}))) == 0 ? [] : [try(default_action.value.redirect, {})]

        content {
          path        = try(redirect.value.path, null)
          host        = try(redirect.value.host, null)
          port        = try(redirect.value.port, null)
          protocol    = try(redirect.value.protocol, null)
          query       = try(redirect.value.query, null)
          status_code = redirect.value["status_code"]
        }
      }

      dynamic "fixed_response" {
        for_each = length(keys(try(default_action.value.fixed_response, {}))) == 0 ? [] : [try(default_action.value.fixed_response, {})]

        content {
          content_type = fixed_response.value["content_type"]
          message_body = try(fixed_response.value.message_body, null)
          status_code  = try(fixed_response.value.status_code, null)
        }
      }

      # Authentication actions only available with HTTPS listeners
      dynamic "authenticate_cognito" {
        for_each = length(keys(try(default_action.value.authenticate_cognito, {}))) == 0 ? [] : [try(default_action.value.authenticate_cognito, {})]

        content {
          # Max 10 extra params
          authentication_request_extra_params = try(authenticate_cognito.value.authentication_request_extra_params, null)
          on_unauthenticated_request          = try(authenticate_cognito.value.on_authenticated_request, null)
          scope                               = try(authenticate_cognito.value.scope, null)
          session_cookie_name                 = try(authenticate_cognito.value.session_cookie_name, null)
          session_timeout                     = try(authenticate_cognito.value.session_timeout, null)
          user_pool_arn                       = authenticate_cognito.value["user_pool_arn"]
          user_pool_client_id                 = authenticate_cognito.value["user_pool_client_id"]
          user_pool_domain                    = authenticate_cognito.value["user_pool_domain"]
        }
      }

      dynamic "authenticate_oidc" {
        for_each = length(keys(try(default_action.value.authenticate_oidc, {}))) == 0 ? [] : [try(default_action.value.authenticate_oidc, {})]

        content {
          # Max 10 extra params
          authentication_request_extra_params = try(authenticate_oidc.value.authentication_request_extra_params, null)
          authorization_endpoint              = authenticate_oidc.value["authorization_endpoint"]
          client_id                           = authenticate_oidc.value["client_id"]
          client_secret                       = authenticate_oidc.value["client_secret"]
          issuer                              = authenticate_oidc.value["issuer"]
          on_unauthenticated_request          = try(authenticate_oidc.value.on_unauthenticated_request, null)
          scope                               = try(authenticate_oidc.value.scope, null)
          session_cookie_name                 = try(authenticate_oidc.value.session_cookie_name, null)
          session_timeout                     = try(authenticate_oidc.value.session_timeout, null)
          token_endpoint                      = authenticate_oidc.value["token_endpoint"]
          user_info_endpoint                  = authenticate_oidc.value["user_info_endpoint"]
        }
      }
    }
  }

  dynamic "default_action" {
    for_each = contains(["authenticate-oidc", "authenticate-cognito"], try(var.https_listeners[count.index].action_type, {})) ? [var.https_listeners[count.index]] : []
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.main[try(default_action.value.target_group_index, count.index)].id
    }
  }

  tags = merge(
    var.tags,
    var.https_listeners_tags,
    try(var.https_listeners[count.index].tags, {}),
  )
}

resource "aws_lb_listener_certificate" "https_listener" {
  count = local.create_lb ? length(var.extra_ssl_certs) : 0

  listener_arn    = aws_lb_listener.frontend_https[var.extra_ssl_certs[count.index]["https_listener_index"]].arn
  certificate_arn = var.extra_ssl_certs[count.index]["certificate_arn"]
}
