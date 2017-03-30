<#
.SYNOPSIS  
 Bootstrap script for creating schedule for Alert creation Runbook
.DESCRIPTION  
 Bootstrap script for creating schedule for Alert creation Runbook
.EXAMPLE  
.\CreateScheduleforAlert.ps1 -AzureLoginUserName "Value1" -AzureLoginPassword "Value2" -ResourceGroupName "Value3" -AutomationAccountName "Value4" -RunbookName "Value5" -ScheduleName "Value6" -SubscriptionId "Value7"
Version History  
v1.0   - redmond\balas - Initial Release  
#>
Param (
    [String]$AzureLoginUserName = $(throw "Value for AzureLoginUserName is missing"),

    [String]$AzureLoginPassword = $(throw "Value for AzureLoginPassword is missing"),

    [String] $ResourceGroupName = $(throw "Value for ResourceGroupName is missing"),

    [String] $AutomationAccountName = $(throw "Value for AutomationAccountName is missing"),

    [String] $RunbookName = $(throw "Value for RunbookName is missing"),

    [String] $ScheduleName = $(throw "Value for ScheduleName is missing"),

    [String] $SubscriptionId = $(throw "Value for SubscriptionId is missing")
)

try
{
    Write-Output "Schedule Creation for the Runbook Started..."
    #-----L O G I N - A U T H E N T I C A T I O N-----
    Write-Output "Logging into Azure Subscription..."

    $secPassword = ConvertTo-SecureString $AzureLoginPassword -AsPlainText -Force
    $AzureOrgIdCredential = New-Object System.Management.Automation.PSCredential($AzureLoginUserName, $secPassword)
    Login-AzureRmAccount -Credential $AzureOrgIdCredential
    $Subscription = Select-AzureRmSubscription -SubscriptionId $SubscriptionId

    Write-Output "Successfully logged into Azure Subscription..."
    
    #-----Configure the Start & End Time----
    $StartTime = (Get-Date).AddMinutes(10)
    $EndTime = $StartTime.AddYears(1)

    #----Set the schedule to run every 8 hours---
    $Hours = 8

    #---Create the schedule at the Automation Account level--- 
    Write-Output "Creating the Schedule ($($ScheduleName)) in Automation Account ($($AutomationAccountName))..."
    New-AzureRmAutomationSchedule –AutomationAccountName $AutomationAccountName –Name $ScheduleName -ResourceGroupName $ResourceGroupName –StartTime $StartTime -ExpiryTime $EndTime -HourInterval $Hours
    
    #Disable the schedule    
    Set-AzureRmAutomationSchedule -AutomationAccountName $AutomationAccountName -Name $ScheduleName -ResourceGroupName $ResourceGroupName -IsEnabled $false
    
    Write-Output "Successfully created the Schedule ($($ScheduleName)) in Automation Account ($($AutomationAccountName))..."

    #---Link the schedule to the runbook--- 
    Write-Output "Registering the Schedule ($($ScheduleName)) in the Runbook ($($RunbookName))..."
    Register-AzureRmAutomationScheduledRunbook –AutomationAccountName $AutomationAccountName –Name $RunbookName –ScheduleName $ScheduleName -ResourceGroupName $ResourceGroupName
    Write-Output "Successfully Registered the Schedule ($($ScheduleName)) in the Runbook ($($RunbookName))..."

    Write-Output "Schedule Creation for the Runbook Completed..."
}
catch
{
    Write-Output "Error Occurred..."   
    Write-Output $_.Exception
}