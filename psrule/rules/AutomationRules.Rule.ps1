Rule "Validate-AutomationRule" {
    # Validate that the Automation Rule has required properties
    $rule = $TargetObject
    $requiredProperties = @("displayName", "order", "triggeringLogic", "actions")

    foreach ($property in $requiredProperties) {
        if (-not $rule.PSObject.Properties[$property]) {
            $rule | Fail -Message "Automation Rule is missing required property: $property"
        }
    }

    # Validate that the order is a positive integer
    if ($rule.order -le 0) {
        $rule | Fail -Message "Automation Rule has an invalid order: $($rule.order)"
    }

    # Validate that the triggering logic has required properties
    $triggeringLogic = $rule.triggeringLogic
    $requiredTriggeringLogicProperties = @("isEnabled", "conditions")
    foreach ($property in $requiredTriggeringLogicProperties) {
        if (-not $triggeringLogic.PSObject.Properties[$property]) {
            $rule | Fail -Message "Triggering Logic is missing required property: $property"
        }
    }

    # Validate that the actions have required properties
    $actions = $rule.actions
    foreach ($action in $actions) {
        $requiredActionProperties = @("actionType", "order")
        foreach ($property in $requiredActionProperties) {
            if (-not $action.PSObject.Properties[$property]) {
                $rule | Fail -Message "Action is missing required property: $property"
            }
        }
    }

    # If all validations pass, the rule is valid
    $rule | Pass -Message "Automation Rule is valid"
}
