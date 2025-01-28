Rule "Validate-AnalyticsRule" {
    # Validate that the Analytics Rule has required properties
    $rule = $TargetObject
    $requiredProperties = @("displayName", "alertRuleTemplateName", "description", "severity", "enabled", "query", "queryFrequency", "queryPeriod", "triggerOperator", "triggerThreshold", "tactics", "incidentConfiguration", "eventGroupingSettings", "entityMappings")

    foreach ($property in $requiredProperties) {
        if (-not $rule.PSObject.Properties[$property]) {
            $rule | Fail -Message "Analytics Rule is missing required property: $property"
        }
    }

    # Validate that the severity is one of the allowed values
    $allowedSeverities = @("High", "Medium", "Low", "Informational")
    if ($allowedSeverities -notcontains $rule.severity) {
        $rule | Fail -Message "Analytics Rule has an invalid severity: $($rule.severity)"
    }

    # Validate that the query frequency and period are in ISO 8601 duration format
    if ($rule.queryFrequency -notmatch "^P(?:\d+Y)?(?:\d+M)?(?:\d+W)?(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?$") {
        $rule | Fail -Message "Analytics Rule has an invalid query frequency: $($rule.queryFrequency)"
    }
    if ($rule.queryPeriod -notmatch "^P(?:\d+Y)?(?:\d+M)?(?:\d+W)?(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?$") {
        $rule | Fail -Message "Analytics Rule has an invalid query period: $($rule.queryPeriod)"
    }

    # Validate that the trigger operator is one of the allowed values
    $allowedTriggerOperators = @("GreaterThan", "LessThan", "Equal", "NotEqual")
    if ($allowedTriggerOperators -notcontains $rule.triggerOperator) {
        $rule | Fail -Message "Analytics Rule has an invalid trigger operator: $($rule.triggerOperator)"
    }

    # Validate that the incident configuration has required properties
    $incidentConfig = $rule.incidentConfiguration
    $requiredIncidentConfigProperties = @("groupingConfiguration", "createIncident")
    foreach ($property in $requiredIncidentConfigProperties) {
        if (-not $incidentConfig.PSObject.Properties[$property]) {
            $rule | Fail -Message "Incident Configuration is missing required property: $property"
        }
    }

    # Validate that the event grouping settings have required properties
    $eventGroupingSettings = $rule.eventGroupingSettings
    $requiredEventGroupingProperties = @("aggregationKind")
    foreach ($property in $requiredEventGroupingProperties) {
        if (-not $eventGroupingSettings.PSObject.Properties[$property]) {
            $rule | Fail -Message "Event Grouping Settings are missing required property: $property"
        }
    }

    # Validate that the entity mappings have required properties
    $entityMappings = $rule.entityMappings
    foreach ($entityMapping in $entityMappings) {
        $requiredEntityMappingProperties = @("entityType", "fieldMappings")
        foreach ($property in $requiredEntityMappingProperties) {
            if (-not $entityMapping.PSObject.Properties[$property]) {
                $rule | Fail -Message "Entity Mapping is missing required property: $property"
            }
        }
    }

    # If all validations pass, the rule is valid
    $rule | Pass -Message "Analytics Rule is valid"
}
