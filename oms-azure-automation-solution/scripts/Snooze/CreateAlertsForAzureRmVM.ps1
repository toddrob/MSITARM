
#-----Function to generate unique alert name-----
function Generate-AlertName 
{
    param ([string] $OldAlertName , 
     [string] $VMName)
         
    [string[]] $AlertSplit = $OldAlertName -split "-"
    [int] $Number =$AlertSplit[$AlertSplit.Length-1]
    $Number++
    $Newalertname = "Alert-$($VMName)-$Number"
    return $Newalertname
}

function CreateOrDisableAlert
{
    param(
        $VMObject,
        [string]$AlertAction,
        [string]$WebhookUri
    )

    $ResourceGroupName =$VMObject.ResourceGroupName
    $Location = $VMObject.Location
    $VMState = (Get-AzureRmVM -ResourceGroupName $VMObject.ResourceGroupName -Name $VMObject.Name -Status -ErrorAction SilentlyContinue).Statuses.Code[1] 
    Write-Output "Processing VM ($($VMObject.Name))"
    Write-Output "Current VM state is ($($VMState))"
    $actionWebhook = New-AzureRmAlertRuleWebhook -ServiceUri $WebhookUri
    $resourceId = "/subscriptions/$($SubId)/resourceGroups/$ResourceGroupName/providers/Microsoft.Compute/virtualMachines/$($VMObject.Name.Trim())"
    $NewAlertName ="Alert-$($VMObject.Name)-1"
                                                 
    if($AlertAction -eq "Disable")
    {
        $ExVMAlerts = Get-AzureRmAlertRule -ResourceGroup $VMObject.ResourceGroupName -DetailedOutput -ErrorAction SilentlyContinue
                 if($ExVMAlerts -ne $null)
                    {
                        Write-Output "Checking for any previous alert(s)..." 
                        #Alerts exists so disable alert
                        foreach($Alert in $ExVMAlerts)
                        {
                                                
                            if($Alert.Name.ToLower().Contains($($VMObject.Name.ToLower().Trim())))
                            {
                                Write-Output "Previous alert ($($Alert.Name)) found and disabling now..." 
                                 Add-AzureRmMetricAlertRule  -Name  $Alert.Name `
                                        -Location  $Alert.Location `
                                        -ResourceGroup $ResourceGroupName `
                                        -TargetResourceId $resourceId `
                                        -MetricName $metricName `
                                        -Operator  $condition `
                                        -Threshold $threshold `
                                        -WindowSize  $timeWindow `
                                        -TimeAggregationOperator $timeAggregationOperator `
                                        -Actions $actionWebhook `
                                        -Description $description -DisableRule 

                                        Write-Output "Alert ($($Alert.Name)) Disabled for VM $($VMObject.Name)"
                                    
                            }
                        }
                           
                    }
    }
    elseif($AlertAction -eq "Create")
    {
        #Getting ResourcegroupName and Location based on VM  
                    
                        if ($VMState -eq 'PowerState/running') 
                        {                     
                            try
                            {
                                $VMAlerts = Get-AzureRmAlertRule -ResourceGroup $ResourceGroupName -DetailedOutput -ErrorAction SilentlyContinue

                                #Check if alerts exists and take action
                                if($VMAlerts -ne $null)
                                {
                                    Write-Output "Checking for any previous alert(s)..." 
                                    #Alerts exists so delete and re-create the new alert
                                    foreach($Alert in $VMAlerts)
                                    {
                                                
                                        if($Alert.Name.ToLower().Contains($($VMObject.Name.ToLower().Trim())))
                                        {
                                            Write-Output "Previous alert ($($Alert.Name)) found and deleting now..." 
                                            #Remove the old alert
                                            Remove-AzureRmAlertRule -Name $Alert.Name -ResourceGroup $ResourceGroupName
                                   
                                            #Wait for few seconds to make sure it processed 
                                            Do
                                            {
                                               #Start-Sleep 10    
                                               $GetAlert=Get-AzureRmAlertRule -ResourceGroup $ResourceGroupName -Name $Alert.Name -DetailedOutput -ErrorAction SilentlyContinue                                       
                                                        
                                            }
                                            while($GetAlert -ne $null)
                                   
                                            Write-Output "Generating a new alert with unique name..."
                                            #Now generate new unique alert name
                                            $NewAlertName = Generate-AlertName -OldAlertName $Alert.Name -VMName $VMObject.Name               
                                    
                                        }
                                     }
                           
                                }
                                 #Alert does not exist, so create new alert
                                 Write-Output $NewAlertName                
                                 
                                 Write-Output "Adding a new alert to the VM..."
                                         
                                 Add-AzureRmMetricAlertRule  -Name  $NewAlertName `
                                        -Location  $location `
                                        -ResourceGroup $ResourceGroupName `
                                        -TargetResourceId $resourceId `
                                        -MetricName $metricName `
                                        -Operator  $condition `
                                        -Threshold $threshold `
                                        -WindowSize  $timeWindow `
                                        -TimeAggregationOperator $timeAggregationOperator `
                                        -Actions $actionWebhook `
                                        -Description $description               
                               
                                           
                               Write-Output  "Alert Created for VM $($VM.Name.Trim())"    
                            }
                            catch
                            {
                             Write-Output "Error Occurred"   
                             Write-Output $_.Exception
                            }
                    
                         }
                         else
                         {
                            Write-Output " $($VM.Name) is De-allocated"
                         }
    }

}
#-----L O G I N - A U T H E N T I C A T I O N-----
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


#---------Read all the input variables---------------
$SubId = Get-AutomationVariable -Name 'AzureSubscriptionId'
$ResourceGroupNames = Get-AutomationVariable -Name 'ResourceGroupNames'
$ExcludeVMNames = Get-AutomationVariable -Name 'ExcludeVMNames'

#-----Prepare the inputs for alert attributes-----
$threshold = Get-AutomationVariable -Name 'Snooze_Threshold'
$metricName = Get-AutomationVariable -Name 'Snooze_MetricName'
$timeWindow = Get-AutomationVariable -Name 'Snooze_TimeWindow'
$condition = Get-AutomationVariable -Name 'Snooze_Condition' # Other valid values are LessThanOrEqual, GreaterThan, GreaterThanOrEqual
$description = Get-AutomationVariable -Name 'Snooze_Description'
$timeAggregationOperator = Get-AutomationVariable -Name 'Snooze_TimeAggregationOperator'
$webhookUri = Get-AutomationVariable -Name 'Snooze_WebhookUri'

try
    {  
            Write-Output "Runbook Execution Started..."
            [string[]] $VMfilterList = $ExcludeVMNames -split ","
            [string[]] $VMRGList = $ResourceGroupNames -split ","

            #Validate the Exclude List VM's and stop the execution if the list contains any invalid VM
            if([string]::IsNullOrEmpty($ExcludeVMNames) -ne $true)
            {
                Write-Output "Exclude VM's added so validating the resource(s)..."
                $AzureVM= Get-AzureRmVM -ErrorAction SilentlyContinue
                [boolean] $ISexists = $false
            
                [string[]] $invalidvm=@()
                $ExAzureVMList=@()

                foreach($filtervm in $VMfilterList)
                {
                    foreach($vmname in $AzureVM)
                    {
                        if($Vmname.Name.ToLower().Trim() -eq $filtervm.Tolower().Trim())
                        {                    
                            $ISexists = $true
                            $ExAzureVMList+=$vmname
                            break                    
                        }
                        else
                        {
                            $ISexists = $false
                        }
                    }
                 if($ISexists -eq $false)
                 {
                    $invalidvm = $invalidvm+$filtervm
                 }
               }

               if($invalidvm -ne $null)
               {
                Write-Output "Runbook Execution Stopped! Invalid VM Name(s) in the exclude list: $($invalidvm) "
                Write-Warning "Runbook Execution Stopped! Invalid VM Name(s) in the exclude list: $($invalidvm) "
                exit
               }
             } 

            foreach($VM in $ExAzureVMList)
            {
                try
                {
                    CreateOrDisableAlert -VMObject $VM -AlertAction "Disable" -WebhookUri $webhookUri
                }
                catch
                {
                   $ex = $_.Exception
                   Write-Output $_.Exception 
                }
            }

            $AzureVMListTemp = $null
            $AzureVMList=@()
            ##Getting VM Details based on RG List or Subscription
            if($VMRGList -ne $null)
            {
              foreach($Resource in $VMRGList)
              {
                   Write-Output "Validating the resource group name ($($Resource.Trim()))" 
                   $checkRGname = Get-AzureRmResourceGroup  $Resource.Trim() -ev notPresent -ea 0  
                   if ($checkRGname -eq $null)
                   {
                     Write-Warning "$($Resource) is not a valid Resource Group Name. Please Verify!"
                   }
                   else
                   {                   
                    $AzureVMListTemp = Get-AzureRmVM -ResourceGroupName $Resource -ErrorAction SilentlyContinue
                    if($AzureVMListTemp -ne $null)
                    {
                        $AzureVMList+=$AzureVMListTemp
                    }
                   }
              }
            } 
            else
            {
              Write-Output "Getting all the VM's from the subscription..."  
              $AzureVMList=Get-AzureRmVM -ErrorAction SilentlyContinue
            }        
           
            foreach($VM in $AzureVMList)
            {  
                ##Checking Vm in excluded list                         
                if($VMfilterList -notcontains ($($VM.Name)))
                {

                    CreateOrDisableAlert -VMObject $VM -AlertAction "Create" -WebhookUri $webhookUri

                }
            }
            Write-Output "Runbook Execution Completed..."
    }
    catch
    {
        $ex = $_.Exception
        Write-Output $_.Exception
        #throw $ex
    }
