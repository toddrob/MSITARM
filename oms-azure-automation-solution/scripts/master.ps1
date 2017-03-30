<#
.SYNOPSIS  
 Bootstrap master script for triggering all the child bootstrap scripts
.DESCRIPTION  
 Bootstrap master script for triggering all the child bootstrap scripts
.EXAMPLE  
.\master.ps1 
Version History  
v1.0   - redmond\balas - Initial Release  
#>


try
{
    Write-Output "Bootstrap wrapper script execution started..."

    Write-Output "Reading the credentials..."

    #---------Read the Credentials variable---------------
    $myCredential = Get-AutomationPSCredential -Name 'AzureCredentials'
    $AzureLoginUserName = $myCredential.UserName
    $securePassword = $myCredential.Password
    $AzureLoginPassword = $myCredential.GetNetworkCredential().Password

    #---------Inputs variables for NewRunAsAccountCertKeyVault.ps1 child bootstrap script--------------
    $automationAccountName = Get-AutomationVariable -Name 'OMSAutomationAccountName'
    $subId = Get-AutomationVariable -Name 'AzureSubscriptionId'
    $omsResourceGroupName = Get-AutomationVariable -Name 'OMSResourceGroupName'


    Write-Output "Calling NewRunAsAccountCertKeyVault.ps1 child bootstrap script to create the certificate and connection asset..."
    .\NewRunAsAccountCertKeyVault.ps1 -AzureLoginUserName $AzureLoginUserName -AzureLoginPassword $AzureLoginPassword -ResourceGroup $omsResourceGroupName -AutomationAccountName $automationAccountName -SubscriptionId $subId 
    Write-Output "Execution completed for NewRunAsAccountCertKeyVault.ps1 ..."

    #---------Inputs variables for CreateStopVMWebhook.ps1 child bootstrap script--------------
    $runbookNameforStopVM = "StopAzureRmVM"
    $webhookNameforStopVM = "StopAzureRmVMWebhook"

    Write-Output "Calling CreateStopVMWebhook.ps1 child bootstrap script to create the webhook for $($runbookName)..."
    .\CreateStopVMWebhook.ps1 -AzureLoginUserName $AzureLoginUserName -AzureLoginPassword $AzureLoginUserName -ResourceGroupName $omsResourceGroupName -AutomationAccountName $automationAccountName -RunbookName $runbookNameforStopVM -WebhookName $webhookNameforStopVM -SubscriptionId $subId
    Write-Output "Execution completed for CreateStopVMWebhook.ps1 ..."    

    Write-Output "Calling CreateScheduleforAlert.ps1 child bootstrap script ..."
    #.\CreateScheduleforAlert.ps1 -RGName $omsResourceGroupName -AutomationAccountName $automationAccountName -RunbookName $runbookNameforCreateAlert -ScheduleName $scheduleNameforCreateAlert -SubscriptionId $subId
      
 
  $connectionName = "AzureRunAsConnection"
    try
    {
        # Get the connection "AzureRunAsConnection "
        $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName         

        "Logging in to Azure..."
        Add-AzureRmAccount `
            -ServicePrincipal `
            -TenantId $servicePrincipalConnection.TenantId `
            -ApplicationId $servicePrincipalConnection.ApplicationId `
            -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint 
    }
    catch 
    {
        if (!$servicePrincipalConnection)
        {
            $ErrorMessage = "Connection $connectionName not found."
            throw $ErrorMessage
        } else{
            Write-Error -Message $_.Exception
            throw $_.Exception
        }
    }
    Write-Output "Successfully logged into Azure Subscription..."
    

    #---------Inputs variables for CreateScheduleforAlert.ps1 child bootstrap script--------------
    $runbookNameforCreateAlert = "CreateAlertsForAzureRmVM"
    $scheduleNameforCreateAlert = "Schedule_CreateAlertsForAzureRmVM"

    #-----Configure the Start & End Time----
    $StartTime = (Get-Date).AddMinutes(10)
    $EndTime = $StartTime.AddYears(1)

    #----Set the schedule to run every 8 hours---
    $Hours = 8

    #---Create the schedule at the Automation Account level--- 
    Write-Output "Creating the Schedule ($($scheduleNameforCreateAlert)) in Automation Account ($($AutomationAccountName))..."
    New-AzureRmAutomationSchedule -AutomationAccountName $AutomationAccountName -Name $scheduleNameforCreateAlert -ResourceGroupName $omsResourceGroupName -StartTime $StartTime -ExpiryTime $EndTime -HourInterval $Hours

    #Disable the schedule    
    Set-AzureRmAutomationSchedule -AutomationAccountName $AutomationAccountName -Name $scheduleNameforCreateAlert -ResourceGroupName $omsResourceGroupName -IsEnabled $false
    
    Write-Output "Successfully created the Schedule ($($scheduleNameforCreateAlert)) in Automation Account ($($AutomationAccountName))..."

    #---Link the schedule to the runbook--- 
    Write-Output "Registering the Schedule ($($scheduleNameforCreateAlert)) in the Runbook ($($runbookNameforCreateAlert))..."
    Register-AzureRmAutomationScheduledRunbook -AutomationAccountName $AutomationAccountName -Name $runbookNameforCreateAlert -ScheduleName $scheduleNameforCreateAlert -ResourceGroupName $omsResourceGroupName
    Write-Output "Successfully Registered the Schedule ($($scheduleNameforCreateAlert)) in the Runbook ($($runbookNameforCreateAlert))..."

    Write-Output "Schedule Creation for the Runbook Completed..."

    Write-Output "Bootstrap wrapper script execution completed..."  
}
catch
{
    Write-Output "Error Occurred..."   
    Write-Output $_.Exception
}