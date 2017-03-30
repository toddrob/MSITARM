
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
$SubId = Get-AutomationVariable -Name 'SubscriptionId'
$ResourceGroupNames = Get-AutomationVariable -Name 'ResourceGroupNames'
$ExcludeVMNames = Get-AutomationVariable -Name 'ExcludeVMNames'

#-----Prepare the inputs for alert attributes-----
$threshold = "10"
$metricName = "Percentage CPU"
$timeWindow = "00:05:00"
$condition = "LessThan" # Other valid values are LessThanOrEqual, GreaterThan, GreaterThanOrEqual
$description = "Alert to stop the VM if the CPU % exceed the threshold"

try
    {  
            [string[]] $VMfilterList = $ExcludeVMNames -split ","
            [string[]] $VMRGList = $ResourceGroupNames -split ","

            #Validate the Exclude List VM's and stop the execution if the list contains any invalid VM
            $AzureVM= Get-AzureRmVM -ErrorAction SilentlyContinue
            [boolean] $ISexists = $false
            
            [string[]] $invalidvm=@()
            foreach($filtervm in $VMfilterList)
            {
                foreach($vmname in $AzureVM)
                {
                    if($Vmname.Name.ToLower() -eq $filtervm.Tolower())
                    {                    
                        $ISexists = $true
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
            $AzureVMListTemp = $null
            $AzureVMList=@()
            ##Getting VM Details based on RG List or Subscription
            if($VMRGList -ne $null)
            {
              foreach($Resource in $VMRGList)
              {
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
              $AzureVMList=Get-AzureRmVM -ErrorAction SilentlyContinue
            }        
           
            foreach($VM in $AzureVMList)
            {  
                ##Checking Vm in excluded list                         
                if($VMfilterList -notcontains ($($VM.Name)))
                {

                    #Getting ResourcegroupName and Location based on VM  
                    $ResourceGroupName =$VM.ResourceGroupName
                    $Location = $VM.Location
                    $VMState = (Get-AzureRmVM -ResourceGroupName $VM.ResourceGroupName -Name $VM.Name -Status -ErrorAction SilentlyContinue).Statuses.Code[1] 
                    Write-Output $VM.Name
                    Write-Output $VMState                 
                        if ($VMState -eq 'PowerState/running') 
                        {                     
                            try
                            {
                                $actionWebhook = New-AzureRmAlertRuleWebhook -ServiceUri "https://s1events.azure-automation.net/webhooks?token=8PwEmmHp9qV%2f3FQ3%2bnUOeq%2b%2bNuJTYANRKgMVtEdBCWQ%3d"
                                $resourceId = "/subscriptions/$($SubId)/resourceGroups/$ResourceGroupName/providers/Microsoft.Compute/virtualMachines/$($VM.Name.Trim())"
                                $VMAlerts = Get-AzureRmAlertRule -ResourceGroup $ResourceGroupName -DetailedOutput -ErrorAction SilentlyContinue
                                $NewAlertName ="Alert-$($VM.Name)-1"
                                #Check if alerts exists and take action
                                if($VMAlerts -ne $null)
                                {
                                    #Alerts exists so delete and re-create the new alert
                                    foreach($Alert in $VMAlerts)
                                    {
                                                
                                        if($Alert.Name.ToLower().Contains($($VM.Name.ToLower().Trim())))
                                        {
                                            #Remove the old alert
                                            Remove-AzureRmAlertRule -Name $Alert.Name -ResourceGroup $ResourceGroupName
                                   
                                            #Wait for few seconds to make sure it processed 
                                            Do
                                            {
                                               Start-Sleep 10    
                                               $GetAlert=Get-AzureRmAlertRule -ResourceGroup $ResourceGroupName -Name $Alert.Name -DetailedOutput -ErrorAction SilentlyContinue                                       
                                                        
                                            }
                                            while($GetAlert -ne $null)
                                   
                                            #Now generate new unique alert name
                                            $NewAlertName = Generate-AlertName -OldAlertName $Alert.Name -VMName $VM.Name                                            
                                    
                                        }
                                     }

                                       Write-Output $NewAlertName    

                                       Add-AzureRmMetricAlertRule  -Name  $NewAlertName `
                                            -Location  $location `
                                            -ResourceGroup $ResourceGroupName `
                                            -TargetResourceId $resourceId `
                                            -MetricName $metricName `
                                            -Operator  $condition `
                                            -Threshold $threshold `
                                            -WindowSize  $timeWindow `
                                            -TimeAggregationOperator Average `
                                            -Actions $actionWebhook `
                                            -Description $description
                           
                               }
                               else
                               {
                                 #Alert does not exist, so create new alert
                                 Write-Output $NewAlertName                
                                         
                                 Add-AzureRmMetricAlertRule  -Name  $NewAlertName `
                                        -Location  $location `
                                        -ResourceGroup $ResourceGroupName `
                                        -TargetResourceId $resourceId `
                                        -MetricName $metricName `
                                        -Operator  $condition `
                                        -Threshold $threshold `
                                        -WindowSize  $timeWindow `
                                        -TimeAggregationOperator Average `
                                        -Actions $actionWebhook `
                                        -Description $description              
                               }
                                           
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
            Write-Output "Execution Completed..."
    }
    catch
    {
        $ex = $_.Exception
        Write-Output $_.Exception
        #throw $ex
    }

