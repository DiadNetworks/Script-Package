$version = "v2.12.7"
#Requires -RunAsAdministrator
#GUI generated with ConvertForm module version 2.0.0
#Need these 2 modules:
#Install-Module -Name Microsoft.Graph -Force -AllowClobber
#Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber

# Settings retrieval function
function LoadSettings {
	Write-Host "Loading settings from settings.ini..."
	Get-Content “.\settings.ini” | foreach-object -begin {$h=@{}; Write-Host "$h"} -process { $k = [regex]::split($_,’=’); if(($k[0].CompareTo(“”) -ne 0)     -and ($k[0].StartsWith(“[“) -ne $True)) { $h.Add($k[0], $k[1]) } }
	$progressBarColor = $h.Get_Item("ProgressBarColor")
	$progressBarType = $h.Get_Item(“ProgressBarType”)
	$enableVisualStyles = $h.Get_Item(“EnableVisualStyles”)

	# Set progress bar color
	if ($progressBarColor -eq "Default") {
		Write-Host "Using default progress bar color."
	}
	else {
		$progressBar1.ForeColor = [System.Drawing.Color]::$progressBarColor
		Write-Host "Set custom progress bar color: $progressBarColor. Note, custom colors only work if EnableVisualStyles is set to 0."
	}
	# Set progress bar style
	if ($progressBarType -eq "Continuous") {
		$progressBar1.Style = "Continuous"
		Write-Host "Set progress bar type to Continuous."
	}
	elseif ($progressBarType -eq "Blocks") {
		$progressBar1.Style = "Blocks"
		Write-Host "Set progress bar type to Blocks. Note, block style only works if EnableVisualStyles is set to 0."
	}
	elseif ($progressBarType -eq "Marquee") {
		$progressBar1.Style = "Marquee"
		Write-Host "Set progress bar style to Marquee. Note, the application is not setup to use this style, progress bar won't work properly."
	}
	else {
		Write-Host "Invalid value, using default progress bar type."
		$progressBar1.Style = "Continuous"
	}
	# Set visual styles
	if ($enableVisualStyles -eq 0) {
		Write-Host "Visual styles are disabled."
	}
	elseif ($enableVisualStyles -eq 1) {
		[System.Windows.Forms.Application]::EnableVisualStyles()
		Write-Host "Visual styles are enabled."
	}
	else {
		Write-Host "Invalid value, using default style."
		[System.Windows.Forms.Application]::EnableVisualStyles()
	}

	Write-Host "Loaded settings."
}

# Color mode function - not used currently
function ChangeFormColor {
	param (
		$color
	)
	# Change the color of the console text (foreground color)
	$Host.UI.RawUI.ForegroundColor = $color

	# Iterate over all form elements and set their foreground color
	foreach ($element in $Host.UI.RawUI.Window.Forms) {
	  if ($element.GetType().Name -eq 'TextBox') {
		$element.ForegroundColor = $color
	  } elseif ($element.GetType().Name -eq 'Button') {
		$element.ForegroundColor = $color
	  } elseif ($element.GetType().Name -eq 'ListBox') {
		$element.ForegroundColor = $color
	  }
	}
}
function UpdateProgressBar {
	param (
		$progressBarValue
	)
	$progressBar1.Value = $progressBarValue
}

# Functions for each script. Might move these into separate ps1 files at some point.
function Add-AuthenticationPhoneMethod {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Add-AuthenticationPhoneMethod.txt"
	Write-Host "Running Add-2FA script..."
	$progressBar1.Value = 10
	function OnAddPhoneButtonClick {
		$progressBar1.Value = 10
		$user = $emailInput.Text
		$phoneNumber = $phoneInput.Text
		$progressBar1.Value = 40
		New-MgUserAuthenticationPhoneMethod -UserId $user -phoneType "mobile" -phoneNumber $phoneNumber
		Write-Host "Added $phoneNumber to $user."
		$progressBar1.Value = 80
		CheckForErrors
		OperationComplete
	}
	function OnOpenTemplateButtonClick {
		Write-Host "Open template button clicked."
		$progressBar1.Value = 10
		Invoke-Item ".\Templates\Add-AuthenticationPhoneMethod.csv"
		$progressBar1.Value = 100
		CheckForErrors
		$progressBar1.Value = 0
	}
	function OnAddBulkPhoneButtonClick {
		Write-Host "AddBulkPhone button clicked."
		$progressBar1.Value = 10
		Import-Csv -Path ".\Templates\Add-AuthenticationPhoneMethod.csv" | ForEach-Object {
			$progressBar1.Value = 20
			$user = $_.Email
			$phoneNumber = $_.Phone
			$progressBar1.Value = 40
			New-MgUserAuthenticationPhoneMethod -UserId $user -phoneType "mobile" -phoneNumber $phoneNumber
			$progressBar1.Value = 80
			Write-Host "Added $phoneNumber to $user."
		}
		CheckForErrors
		OperationComplete
	}

	$scriptForm8 = New-Object System.Windows.Forms.Form

	$groupBox1 = New-Object System.Windows.Forms.GroupBox
	$emailInput = New-Object System.Windows.Forms.TextBox
	$label1 = New-Object System.Windows.Forms.Label
	$phoneInput = New-Object System.Windows.Forms.TextBox
	$label2 = New-Object System.Windows.Forms.Label
	$addPhoneButton = New-Object System.Windows.Forms.Button
	$groupBox2 = New-Object System.Windows.Forms.GroupBox
	$openTemplateButton = New-Object System.Windows.Forms.Button
	$addBulkPhoneButton = New-Object System.Windows.Forms.Button
	#
	# groupBox1
	#
	$groupBox1.Controls.Add($addPhoneButton)
	$groupBox1.Controls.Add($label2)
	$groupBox1.Controls.Add($phoneInput)
	$groupBox1.Controls.Add($label1)
	$groupBox1.Controls.Add($emailInput)
	$groupBox1.Location = New-Object System.Drawing.Point(12, 12)
	$groupBox1.Name = "groupBox1"
	$groupBox1.Size = New-Object System.Drawing.Size(266, 100)
	$groupBox1.TabIndex = 0
	$groupBox1.TabStop = $false
	$groupBox1.Text = "Single"
	#
	# emailInput
	#
	$emailInput.Location = New-Object System.Drawing.Point(60, 19)
	$emailInput.Name = "emailInput"
	$emailInput.Size = New-Object System.Drawing.Size(200, 20)
	$emailInput.TabIndex = 0
	#
	# label1
	#
	$label1.AutoSize = $true
	$label1.Location = New-Object System.Drawing.Point(6, 22)
	$label1.Name = "label1"
	$label1.Size = New-Object System.Drawing.Size(48, 13)
	$label1.TabIndex = 1
	$label1.Text = "Email:"
	#
	# phoneInput
	#
	$phoneInput.Location = New-Object System.Drawing.Point(60, 45)
	$phoneInput.Name = "phoneInput"
	$phoneInput.Size = New-Object System.Drawing.Size(200, 20)
	$phoneInput.TabIndex = 2
	$phoneInput.PlaceholderText = "Example: +1 2224446666"
	#
	# label2
	#
	$label2.AutoSize = $true
	$label2.Location = New-Object System.Drawing.Point(6, 48)
	$label2.Name = "label2"
	$label2.Size = New-Object System.Drawing.Size(39, 13)
	$label2.TabIndex = 3
	$label2.Text = "Phone:"
	#
	# addPhoneButton
	#
	$addPhoneButton.Location = New-Object System.Drawing.Point(6, 71)
	$addPhoneButton.Name = "addPhoneButton"
	$addPhoneButton.Size = New-Object System.Drawing.Size(254, 23)
	$addPhoneButton.TabIndex = 4
	$addPhoneButton.Text = "Add Phone Number"
	$addPhoneButton.UseVisualStyleBackColor = $true
	$addPhoneButton.Add_Click({ OnAddPhoneButtonClick })
	#
	# groupBox2
	#
	$groupBox2.Controls.Add($addBulkPhoneButton)
	$groupBox2.Controls.Add($openTemplateButton)
	$groupBox2.Location = New-Object System.Drawing.Point(12, 118)
	$groupBox2.Name = "groupBox2"
	$groupBox2.Size = New-Object System.Drawing.Size(266, 77)
	$groupBox2.TabIndex = 5
	$groupBox2.TabStop = $false
	$groupBox2.Text = "Bulk"
	#
	# openTemplateButton
	#
	$openTemplateButton.Location = New-Object System.Drawing.Point(6, 19)
	$openTemplateButton.Name = "openTemplateButton"
	$openTemplateButton.Size = New-Object System.Drawing.Size(254, 23)
	$openTemplateButton.TabIndex = 5
	$openTemplateButton.Text = "Open Template"
	$openTemplateButton.UseVisualStyleBackColor = $true
	$openTemplateButton.Add_Click({ OnOpenTemplateButtonClick })
	#
	# addBulkPhoneButton
	#
	$addBulkPhoneButton.Location = New-Object System.Drawing.Point(6, 48)
	$addBulkPhoneButton.Name = "addBulkPhoneButton"
	$addBulkPhoneButton.Size = New-Object System.Drawing.Size(254, 23)
	$addBulkPhoneButton.TabIndex = 6
	$addBulkPhoneButton.Text = "Add Phone Numbers"
	$addBulkPhoneButton.UseVisualStyleBackColor = $true
	$addBulkPhoneButton.Add_Click({ OnAddBulkPhoneButtonClick })
	#
	# scriptForm8
	#
	$scriptForm8.ClientSize = New-Object System.Drawing.Size(290, 207)
	$scriptForm8.Controls.Add($groupBox2)
	$scriptForm8.Controls.Add($groupBox1)
	$scriptForm8.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$scriptForm8.HelpButton = $false
	$scriptForm8.MaximizeBox = $false
	$scriptForm8.MinimizeBox = $false
	$scriptForm8.Name = "scriptForm8"
	$scriptForm8.ShowIcon = $false
	$scriptForm8.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$scriptForm8.Text = "Add-AuthenticationPhoneMethod"
	$scriptForm8.Add_Shown({$scriptForm8.Activate()})

	Write-Host "Loaded ScriptForm8."
	$progressBar1.Value = 0

	$scriptForm8.ShowDialog()
	$scriptForm8.Dispose()

	Stop-Transcript
}
function Add-AutoReply {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Add-AutoReply.txt"
	Write-Host "Running Add-AutoReply script..."

	function OnConfirmAutoReplyButtonClick {
		$progressBar1.Value = 20
		Write-Host "ConfirmAutoReplyButton clicked, adding auto-replies..."
		$internalMessage = $internalReplyTextBox.Text
		$externalMessage = $externalReplyTextBox.Text
		$mailbox = $emailInputBox.Text

		if ($useScheduleCheckBox.Checked -eq $true) {
			Write-Host "Use schedule is checked, creating auto-reply with schedule..."
			$startTime = $startDatePicker.Value
			$endTime = $endDatePicker.Value
			Set-MailboxAutoReplyConfiguration -Identity $mailbox -AutoReplyState Scheduled -StartTime $startTime -EndTime $endTime -InternalMessage $internalMessage -ExternalMessage $externalMessage -ExternalAudience All -Confirm:$false
			$progressBar1.Value = 50
		}
		else {
			Write-Host "Use schedule isn't checked, creating auto-reply..."
			Set-MailboxAutoReplyConfiguration -Identity $mailbox -AutoReplyState Enabled -InternalMessage $internalMessage -ExternalMessage $externalMessage -ExternalAudience All -Confirm:$false
			$progressBar1.Value = 50
		}
		CheckForErrors
		OperationComplete
	}

	$addAutoReplyForm = New-Object System.Windows.Forms.Form

	$internalReplyLabel = New-Object System.Windows.Forms.Label
	$internalReplyTextBox = New-Object System.Windows.Forms.TextBox
	$externalReplyTextBox = New-Object System.Windows.Forms.TextBox
	$externalReplyLabel = New-Object System.Windows.Forms.Label
	$matchRepliesCheckBox = New-Object System.Windows.Forms.CheckBox
	$confirmAutoReplyButton = New-Object System.Windows.Forms.Button
	$startDatePicker = New-Object System.Windows.Forms.DateTimePicker
	$useScheduleCheckBox = New-Object System.Windows.Forms.CheckBox
	$endDatePicker = New-Object System.Windows.Forms.DateTimePicker
	$startDateLabel = New-Object System.Windows.Forms.Label
	$endDateLabel = New-Object System.Windows.Forms.Label
	$emailLabel = New-Object System.Windows.Forms.Label
	$emailInputBox = New-Object System.Windows.Forms.TextBox
	#
	# internalReplyLabel
	#
	$internalReplyLabel.AutoSize = $true
	$internalReplyLabel.Location = New-Object System.Drawing.Point(8, 42)
	$internalReplyLabel.Name = "internalReplyLabel"
	$internalReplyLabel.Size = New-Object System.Drawing.Size(100, 13)
	$internalReplyLabel.TabIndex = 2
	$internalReplyLabel.Text = "Internal Auto-Reply:"
	#
	# internalReplyTextBox
	#
	$internalReplyTextBox.Location = New-Object System.Drawing.Point(12, 59)
	$internalReplyTextBox.Multiline = $true
	$internalReplyTextBox.Name = "internalReplyTextBox"
	$internalReplyTextBox.Size = New-Object System.Drawing.Size(200, 224)
	$internalReplyTextBox.TabIndex = 3
	$internalReplyTextBox.Add_TextChanged({
		if ($matchRepliesCheckBox.Checked -eq $true) {$externalReplyTextBox.Text = $internalReplyTextBox.Text}
	})
	#
	# externalReplyTextBox
	#
	$externalReplyTextBox.Location = New-Object System.Drawing.Point(222, 59)
	$externalReplyTextBox.Multiline = $true
	$externalReplyTextBox.Name = "externalReplyTextBox"
	$externalReplyTextBox.Size = New-Object System.Drawing.Size(200, 224)
	$externalReplyTextBox.TabIndex = 5
	$externalReplyTextBox.Add_TextChanged({
		if ($matchRepliesCheckBox.Checked -eq $true) {$internalReplyTextBox.Text = $externalReplyTextBox.Text}
	})
	#
	# externalReplyLabel
	#
	$externalReplyLabel.AutoSize = $true
	$externalReplyLabel.Location = New-Object System.Drawing.Point(218, 42)
	$externalReplyLabel.Name = "externalReplyLabel"
	$externalReplyLabel.Size = New-Object System.Drawing.Size(103, 13)
	$externalReplyLabel.TabIndex = 4
	$externalReplyLabel.Text = "External Auto-Reply:"
	#
	# matchRepliesCheckBox
	#
	$matchRepliesCheckBox.AutoSize = $true
	$matchRepliesCheckBox.Checked = $true
	$matchRepliesCheckBox.CheckState = [System.Windows.Forms.CheckState]::Checked
	$matchRepliesCheckBox.Location = New-Object System.Drawing.Point(11, 292)
	$matchRepliesCheckBox.Name = "matchRepliesCheckBox"
	$matchRepliesCheckBox.Size = New-Object System.Drawing.Size(94, 17)
	$matchRepliesCheckBox.TabIndex = 6
	$matchRepliesCheckBox.Text = "Match Replies"
	$matchRepliesCheckBox.UseVisualStyleBackColor = $true
	#
	# confirmAutoReplyButton
	#
	$confirmAutoReplyButton.Location = New-Object System.Drawing.Point(11, 341)
	$confirmAutoReplyButton.Name = "confirmAutoReplyButton"
	$confirmAutoReplyButton.Size = New-Object System.Drawing.Size(410, 28)
	$confirmAutoReplyButton.TabIndex = 12
	$confirmAutoReplyButton.Text = "Confirm"
	$confirmAutoReplyButton.UseVisualStyleBackColor = $true
	$confirmAutoReplyButton.Add_Click({OnConfirmAutoReplyButtonClick})
	#
	# startDatePicker
	#
	$startDatePicker.Enabled = $false
	$startDatePicker.Location = New-Object System.Drawing.Point(221, 289)
	$startDatePicker.Name = "startDatePicker"
	$startDatePicker.Size = New-Object System.Drawing.Size(200, 20)
	$startDatePicker.TabIndex = 9
	#
	# useScheduleCheckBox
	#
	$useScheduleCheckBox.AutoSize = $true
	$useScheduleCheckBox.Location = New-Object System.Drawing.Point(11, 318)
	$useScheduleCheckBox.Name = "useScheduleCheckBox"
	$useScheduleCheckBox.Size = New-Object System.Drawing.Size(139, 17)
	$useScheduleCheckBox.TabIndex = 7
	$useScheduleCheckBox.Text = "Use Start and End Date"
	$useScheduleCheckBox.UseVisualStyleBackColor = $true
	$useScheduleCheckBox.Add_CheckedChanged({
		if ($useScheduleCheckBox.Checked -eq $true) {
			$startDatePicker.Enabled = $true
			$endDatePicker.Enabled = $true
		}
		else {
			$startDatePicker.Enabled = $false
			$endDatePicker.Enabled = $false
		}
	})
	#
	# endDatePicker
	#
	$endDatePicker.Enabled = $false
	$endDatePicker.Location = New-Object System.Drawing.Point(221, 315)
	$endDatePicker.Name = "endDatePicker"
	$endDatePicker.Size = New-Object System.Drawing.Size(200, 20)
	$endDatePicker.TabIndex = 11
	#
	# startDateLabel
	#
	$startDateLabel.AutoSize = $true
	$startDateLabel.Location = New-Object System.Drawing.Point(183, 292)
	$startDateLabel.Name = "startDateLabel"
	$startDateLabel.Size = New-Object System.Drawing.Size(32, 13)
	$startDateLabel.TabIndex = 8
	$startDateLabel.Text = "Start:"
	#
	# endDateLabel
	#
	$endDateLabel.AutoSize = $true
	$endDateLabel.Location = New-Object System.Drawing.Point(183, 318)
	$endDateLabel.Name = "endDateLabel"
	$endDateLabel.Size = New-Object System.Drawing.Size(29, 13)
	$endDateLabel.TabIndex = 10
	$endDateLabel.Text = "End:"
	#
	# emailLabel
	#
	$emailLabel.AutoSize = $true
	$emailLabel.Location = New-Object System.Drawing.Point(91, 15)
	$emailLabel.Name = "emailLabel"
	$emailLabel.Size = New-Object System.Drawing.Size(46, 13)
	$emailLabel.TabIndex = 0
	$emailLabel.Text = "Mailbox:"
	#
	# emailInputBox
	#
	$emailInputBox.Location = New-Object System.Drawing.Point(143, 12)
	$emailInputBox.Name = "emailInputBox"
	$emailInputBox.Size = New-Object System.Drawing.Size(200, 20)
	$emailInputBox.TabIndex = 1
	#
	# addAutoReplyForm
	#
	$addAutoReplyForm.ClientSize = New-Object System.Drawing.Size(434, 381)
	$addAutoReplyForm.Controls.Add($emailInputBox)
	$addAutoReplyForm.Controls.Add($emailLabel)
	$addAutoReplyForm.Controls.Add($endDateLabel)
	$addAutoReplyForm.Controls.Add($startDateLabel)
	$addAutoReplyForm.Controls.Add($endDatePicker)
	$addAutoReplyForm.Controls.Add($useScheduleCheckBox)
	$addAutoReplyForm.Controls.Add($startDatePicker)
	$addAutoReplyForm.Controls.Add($confirmAutoReplyButton)
	$addAutoReplyForm.Controls.Add($matchRepliesCheckBox)
	$addAutoReplyForm.Controls.Add($externalReplyLabel)
	$addAutoReplyForm.Controls.Add($externalReplyTextBox)
	$addAutoReplyForm.Controls.Add($internalReplyTextBox)
	$addAutoReplyForm.Controls.Add($internalReplyLabel)
	$addAutoReplyForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$addAutoReplyForm.MaximizeBox = $false
	$addAutoReplyForm.MinimizeBox = $false
	$addAutoReplyForm.Name = "addAutoReplyForm"
	$addAutoReplyForm.Text = "Add-AutoReply"
	$addAutoReplyForm.Add_Shown({$addAutoReplyForm.Activate()})

	$addAutoReplyForm.ShowDialog()
	$addAutoReplyForm.Dispose()

	Stop-Transcript
}
function Add-Contacts {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Add-Contacts.txt"
	Write-Host "Running Add-Contacts script..."
	UpdateProgressBar(10)
	$addContactsMode = New-Object PSObject -Property @{ Value = 0 }
	function OnAddContactButtonClick {
		Write-Host "AddContact button clicked."
		UpdateProgressBar(10)
		if ($addContactsMode.Value -eq 0) {
			$displayName = $nameInputBox.Text
			$splitName = $displayName -Split ' '
			$firstName = $splitName[0]
			$lastName = $splitName[1]
			$externalEmailAddress = $emailInputBox.Text
			UpdateProgressBar(50)
			New-MailContact -Name $displayName -DisplayName $displayName -ExternalEmailAddress $externalEmailAddress -FirstName $firstName -LastName $lastName
			UpdateProgressBar(90)
		} elseif ($addContactsMode.Value -eq 1) {
			$externalEmailAddress = $emailInputBox.Text
			UpdateProgressBar(50)
			New-MailContact -Name $externalEmailAddress -ExternalEmailAddress $externalEmailAddress
			UpdateProgressBar(90)
		}
		CheckForErrors
		OperationComplete
	}
	function OnBulkContactsButtonClick {
		Write-Host "AddContactsBulk button clicked."
		$progressBar1.Value = 5
		if ($addContactsMode.Value -eq 0) {
			Import-Csv ".\Templates\Add-Contacts.csv" | ForEach-Object {
				$displayName = $_.DisplayName
				$splitName = $displayName -Split ' '
				$firstName = $splitName[0]
				$lastName = $splitName[1]
				$externalEmailAddress = $_.EmailAddress
				UpdateProgressBar(40)
				New-MailContact -Name $displayName -DisplayName $displayName -ExternalEmailAddress $externalEmailAddress -FirstName $firstName -LastName $lastName
				UpdateProgressBar(70)
			}
		} elseif ($addContactsMode.Value -eq 1) {
			Get-Content ".\Templates\Add-Contacts.txt" | ForEach-Object {
				UpdateProgressBar(10)
				New-MailContact -Name $_ -ExternalEmailAddress $_
				UpdateProgressBar(70)
			}
		}
		CheckForErrors
		OperationComplete
	}
	function OnOpenTemplateButtonClick {
		Write-Host "OpenTemplate button clicked."
		UpdateProgressBar(10)
		if ($addContactsMode.Value -eq 0) {
			Invoke-Item ".\Templates\Add-Contacts.csv"
		} elseif ($addContactsMode.Value -eq 1) {
			Invoke-Item ".\Templates\Add-Contacts.txt"
		}
		UpdateProgressBar(80)
		CheckForErrors
		UpdateProgressBar(0)
	}
	function OnRadioButtonSelect {
		if ($allInfoRadioButton.Checked -eq $true) {
			$addContactsMode.Value = 0
			$nameInputBox.Enabled = $true
		} elseif ($justEmailRadioButton.Checked -eq $true) {
			$addContactsMode.Value = 1
			$nameInputBox.Enabled = $false
		}
		Write-Host "Mode = $($addContactsMode.Value)"
		CheckForErrors
	}
	$scriptForm10 = New-Object System.Windows.Forms.Form

	$justEmailRadioButton = New-Object System.Windows.Forms.RadioButton
	$allInfoRadioButton = New-Object System.Windows.Forms.RadioButton
	$modeGroupBox = New-Object System.Windows.Forms.GroupBox
	$bulkGroupBox = New-Object System.Windows.Forms.GroupBox
	$bulkContactsButton = New-Object System.Windows.Forms.Button
	$openTemplateButton = New-Object System.Windows.Forms.Button
	$singleGroupBox = New-Object System.Windows.Forms.GroupBox
	$addContactButton = New-Object System.Windows.Forms.Button
	$nameLabel = New-Object System.Windows.Forms.Label
	$emailLabel = New-Object System.Windows.Forms.Label
	$emailInputBox = New-Object System.Windows.Forms.TextBox
	$nameInputBox = New-Object System.Windows.Forms.TextBox
	#
	# justEmailRadioButton
	#
	$justEmailRadioButton.AutoSize = $true
	$justEmailRadioButton.Location = New-Object System.Drawing.Point(6, 42)
	$justEmailRadioButton.Name = "justEmailRadioButton"
	$justEmailRadioButton.Size = New-Object System.Drawing.Size(71, 17)
	$justEmailRadioButton.TabIndex = 1
	$justEmailRadioButton.Text = "Just email"
	$justEmailRadioButton.UseVisualStyleBackColor = $true
	$justEmailRadioButton.Add_CheckedChanged{( OnRadioButtonSelect )}
	#
	# allInfoRadioButton
	#
	$allInfoRadioButton.AutoSize = $true
	$allInfoRadioButton.Checked = $true
	$allInfoRadioButton.Location = New-Object System.Drawing.Point(6, 19)
	$allInfoRadioButton.Name = "allInfoRadioButton"
	$allInfoRadioButton.Size = New-Object System.Drawing.Size(56, 17)
	$allInfoRadioButton.TabIndex = 0
	$allInfoRadioButton.TabStop = $true
	$allInfoRadioButton.Text = "All info"
	$allInfoRadioButton.UseVisualStyleBackColor = $true
	$allInfoRadioButton.Add_CheckedChanged{( OnRadioButtonSelect )}
	#
	# modeGroupBox
	#
	$modeGroupBox.Controls.Add($justEmailRadioButton)
	$modeGroupBox.Controls.Add($allInfoRadioButton)
	$modeGroupBox.Location = New-Object System.Drawing.Point(12, 12)
	$modeGroupBox.Name = "modeGroupBox"
	$modeGroupBox.Size = New-Object System.Drawing.Size(280, 68)
	$modeGroupBox.TabIndex = 0
	$modeGroupBox.TabStop = $false
	$modeGroupBox.Text = "Mode"
	#
	# bulkGroupBox
	#
	$bulkGroupBox.Controls.Add($bulkContactsButton)
	$bulkGroupBox.Controls.Add($openTemplateButton)
	$bulkGroupBox.Location = New-Object System.Drawing.Point(12, 196)
	$bulkGroupBox.Name = "bulkGroupBox"
	$bulkGroupBox.Size = New-Object System.Drawing.Size(280, 77)
	$bulkGroupBox.TabIndex = 5
	$bulkGroupBox.TabStop = $false
	$bulkGroupBox.Text = "Bulk"
	#
	# bulkContactsButton
	#
	$bulkContactsButton.Location = New-Object System.Drawing.Point(6, 48)
	$bulkContactsButton.Name = "bulkContactsButton"
	$bulkContactsButton.Size = New-Object System.Drawing.Size(268, 23)
	$bulkContactsButton.TabIndex = 6
	$bulkContactsButton.Text = "Add Contacts"
	$bulkContactsButton.UseVisualStyleBackColor = $true
	$bulkContactsButton.Add_Click{( OnBulkContactsButtonClick )}
	#
	# openTemplateButton
	#
	$openTemplateButton.Location = New-Object System.Drawing.Point(6, 19)
	$openTemplateButton.Name = "openTemplateButton"
	$openTemplateButton.Size = New-Object System.Drawing.Size(268, 23)
	$openTemplateButton.TabIndex = 5
	$openTemplateButton.Text = "Open Template"
	$openTemplateButton.UseVisualStyleBackColor = $true
	$openTemplateButton.Add_Click{( OnOpenTemplateButtonClick )}
	#
	# singleGroupBox
	#
	$singleGroupBox.Controls.Add($addContactButton)
	$singleGroupBox.Controls.Add($nameLabel)
	$singleGroupBox.Controls.Add($emailLabel)
	$singleGroupBox.Controls.Add($emailInputBox)
	$singleGroupBox.Controls.Add($nameInputBox)
	$singleGroupBox.Location = New-Object System.Drawing.Point(12, 86)
	$singleGroupBox.Name = "singleGroupBox"
	$singleGroupBox.Size = New-Object System.Drawing.Size(280, 104)
	$singleGroupBox.TabIndex = 2
	$singleGroupBox.TabStop = $false
	$singleGroupBox.Text = "Single"
	#
	# addContactButton
	#
	$addContactButton.Location = New-Object System.Drawing.Point(6, 71)
	$addContactButton.Name = "addContactButton"
	$addContactButton.Size = New-Object System.Drawing.Size(268, 23)
	$addContactButton.TabIndex = 4
	$addContactButton.Text = "Add Contact"
	$addContactButton.UseVisualStyleBackColor = $true
	$addContactButton.Add_Click{( OnAddContactButtonClick )}
	#
	# nameLabel
	#
	$nameLabel.AutoSize = $true
	$nameLabel.Location = New-Object System.Drawing.Point(6, 22)
	$nameLabel.Name = "nameLabel"
	$nameLabel.Size = New-Object System.Drawing.Size(38, 13)
	$nameLabel.TabIndex = 2
	$nameLabel.Text = "Name:"
	#
	# emailLabel
	#
	$emailLabel.AutoSize = $true
	$emailLabel.Location = New-Object System.Drawing.Point(6, 49)
	$emailLabel.Name = "emailLabel"
	$emailLabel.Size = New-Object System.Drawing.Size(35, 13)
	$emailLabel.TabIndex = 3
	$emailLabel.Text = "Email:"
	#
	# emailInputBox
	#
	$emailInputBox.Location = New-Object System.Drawing.Point(50, 45)
	$emailInputBox.Name = "emailInputBox"
	$emailInputBox.Size = New-Object System.Drawing.Size(224, 20)
	$emailInputBox.TabIndex = 2
	#
	# nameInputBox
	#
	$nameInputBox.Location = New-Object System.Drawing.Point(50, 19)
	$nameInputBox.Name = "nameInputBox"
	$nameInputBox.Size = New-Object System.Drawing.Size(224, 20)
	$nameInputBox.TabIndex = 3
	#
	# scriptForm10
	#
	$scriptForm10.ClientSize = New-Object System.Drawing.Size(304, 285)
	$scriptForm10.Controls.Add($singleGroupBox)
	$scriptForm10.Controls.Add($bulkGroupBox)
	$scriptForm10.Controls.Add($modeGroupBox)
	$scriptForm10.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$scriptForm10.MaximizeBox = $false
	$scriptForm10.MinimizeBox = $false
	$scriptForm10.Name = "scriptForm10"
	$scriptForm10.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$scriptForm10.Text = "Add-Contacts"
	$scriptForm10.Add_Shown({$scriptForm10.Activate()})

	Write-Host "Loaded ScriptForm10."
	UpdateProgressBar(0)

	$scriptForm10.ShowDialog()
	$scriptForm10.Dispose()

	Stop-Transcript
}
function Add-DistributionListMember {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Add-DistributionListMember.txt"
	Write-Host "Running Add-DistributionListMember script..."
	$progressBar1.Value = 10
	function OnAddMemberButtonClick {
		Write-Host "AddMemberButton clicked."
		$progressBar1.Value = 20
		$member = $memberInputBox.Text
		$group = $groupInputBox.Text
		$progressBar1.Value = 40
		Add-DistributionGroupMember -Identity $group -Member $member
		Write-Host "Adding $member..."
		$progressBar1.Value = 80
		CheckForErrors
		OperationComplete
	}
	function OnOpenTemplateButtonClick {
		Write-Host "OpenTemplateButton clicked."
		$progressBar1.Value = 10
		Invoke-Item ".\Templates\Add-DistributionListMember.csv"
		$progressBar1.Value = 100
		CheckForErrors
		$progressBar1.Value = 0
	}
	function OnAddBulkMembersButtonClick {
		Write-Host "AddBulkMembersButton clicked."
		$progressBar1.Value = 10
		Import-Csv ".\Templates\Add-DistributionListMember.csv" | ForEach-Object {
			$progressBar1.Value = 20
			$member = $_.Member
			$group = $_.Group
			Add-DistributionGroupMember -Identity $group -Member $member
			Write-Host "Adding $member ..."
			$progressBar1.Value = 80
		}
		CheckForErrors
		OperationComplete
	}
	
	$scriptForm8 = New-Object System.Windows.Forms.Form
	
	$groupBox1 = New-Object System.Windows.Forms.GroupBox
	$memberInputBox = New-Object System.Windows.Forms.TextBox
	$label1 = New-Object System.Windows.Forms.Label
	$groupInputBox = New-Object System.Windows.Forms.TextBox
	$label2 = New-Object System.Windows.Forms.Label
	$addMemberButton = New-Object System.Windows.Forms.Button
	$groupBox2 = New-Object System.Windows.Forms.GroupBox
	$openTemplateButton = New-Object System.Windows.Forms.Button
	$addBulkMembersButton = New-Object System.Windows.Forms.Button
	#
	# groupBox1
	#
	$groupBox1.Controls.Add($addMemberButton)
	$groupBox1.Controls.Add($label2)
	$groupBox1.Controls.Add($groupInputBox)
	$groupBox1.Controls.Add($label1)
	$groupBox1.Controls.Add($memberInputBox)
	$groupBox1.Location = New-Object System.Drawing.Point(12, 12)
	$groupBox1.Name = "groupBox1"
	$groupBox1.Size = New-Object System.Drawing.Size(266, 100)
	$groupBox1.TabIndex = 0
	$groupBox1.TabStop = $false
	$groupBox1.Text = "Single"
	#
	# memberInputBox
	#
	$memberInputBox.Location = New-Object System.Drawing.Point(60, 19)
	$memberInputBox.Name = "memberInputBox"
	$memberInputBox.Size = New-Object System.Drawing.Size(200, 20)
	$memberInputBox.TabIndex = 0
	#
	# label1
	#
	$label1.AutoSize = $true
	$label1.Location = New-Object System.Drawing.Point(6, 22)
	$label1.Name = "label1"
	$label1.Size = New-Object System.Drawing.Size(48, 13)
	$label1.TabIndex = 0
	$label1.Text = "Member:"
	#
	# groupInputBox
	#
	$groupInputBox.Location = New-Object System.Drawing.Point(60, 45)
	$groupInputBox.Name = "groupInputBox"
	$groupInputBox.Size = New-Object System.Drawing.Size(200, 20)
	$groupInputBox.TabIndex = 1
	#
	# label2
	#
	$label2.AutoSize = $true
	$label2.Location = New-Object System.Drawing.Point(6, 48)
	$label2.Name = "label2"
	$label2.Size = New-Object System.Drawing.Size(39, 13)
	$label2.TabIndex = 1
	$label2.Text = "Group:"
	#
	# addMemberButton
	#
	$addMemberButton.Location = New-Object System.Drawing.Point(6, 71)
	$addMemberButton.Name = "addMemberButton"
	$addMemberButton.Size = New-Object System.Drawing.Size(254, 23)
	$addMemberButton.TabIndex = 2
	$addMemberButton.Text = "Add Member"
	$addMemberButton.UseVisualStyleBackColor = $true
	$addMemberButton.Add_Click({OnAddMemberButtonClick})
	#
	# groupBox2
	#
	$groupBox2.Controls.Add($addBulkMembersButton)
	$groupBox2.Controls.Add($openTemplateButton)
	$groupBox2.Location = New-Object System.Drawing.Point(12, 118)
	$groupBox2.Name = "groupBox2"
	$groupBox2.Size = New-Object System.Drawing.Size(266, 77)
	$groupBox2.TabIndex = 3
	$groupBox2.TabStop = $false
	$groupBox2.Text = "Bulk"
	#
	# openTemplateButton
	#
	$openTemplateButton.Location = New-Object System.Drawing.Point(6, 19)
	$openTemplateButton.Name = "openTemplateButton"
	$openTemplateButton.Size = New-Object System.Drawing.Size(254, 23)
	$openTemplateButton.TabIndex = 3
	$openTemplateButton.Text = "Open Template"
	$openTemplateButton.UseVisualStyleBackColor = $true
	$openTemplateButton.Add_Click({OnOpenTemplateButtonClick})
	#
	# addBulkMembersButton
	#
	$addBulkMembersButton.Location = New-Object System.Drawing.Point(6, 48)
	$addBulkMembersButton.Name = "addBulkMembersButton"
	$addBulkMembersButton.Size = New-Object System.Drawing.Size(254, 23)
	$addBulkMembersButton.TabIndex = 4
	$addBulkMembersButton.Text = "Add Members"
	$addBulkMembersButton.UseVisualStyleBackColor = $true
	$addBulkMembersButton.Add_Click({OnAddBulkMembersButtonClick})
	#
	# scriptForm8
	#
	$scriptForm8.ClientSize = New-Object System.Drawing.Size(290, 207)
	$scriptForm8.Controls.Add($groupBox2)
	$scriptForm8.Controls.Add($groupBox1)
	$scriptForm8.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$scriptForm8.HelpButton = $false
	$scriptForm8.MaximizeBox = $false
	$scriptForm8.MinimizeBox = $false
	$scriptForm8.Name = "scriptForm8"
	$scriptForm8.ShowIcon = $false
	$scriptForm8.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$scriptForm8.Text = "Add-DistributionListMember"
	$scriptForm8.Add_Shown({$scriptForm8.Activate()})

	Write-Host "Loaded ScriptForm8."
	$progressBar1.Value = 0

	$scriptForm8.ShowDialog()
	$scriptForm8.Dispose()

	Stop-Transcript
}
function Add-EmailAlias {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Add-EmailAlias.txt"
	Write-Host "Running Add-EmailAlias script..."
	$progressBar1.Value = 10

	function OnAddAliasButtonClick {
		Write-Host "AddAliasButton clicked."
		switch ($incrementalCheckBox.Checked) {
			$true {
				Write-Host "Creating incremental aliases..."
				$progressBar1.Value = 10
				$mailbox = $mailboxTextBox.Text
				$alias = $aliasTextBox.Text
				$splitAlias = $alias -split '\@'
				$aliasName = $splitAlias[0]
				$aliasDomain = $splitAlias[1]
				$progressBar1.Value = 30
				for ($i = 0; $i -lt $numericUpDown1.Value; $i++) {
					$progressBar1.Value = 10
					$completeAlias = $aliasName + [string]$i + "@" + $aliasDomain
					Set-Mailbox $mailbox -EmailAddresses @{Add= $completeAlias}
					Write-Host "Added $completeAlias to $mailbox."
					$progressBar1.Value = 90
				}
				$progressBar1.Value = 90
				CheckForErrors
				OperationComplete
			}
			$false {
				Write-Host "Creating single alias..."
				$progressBar1.Value = 10
				$mailbox = $mailboxTextBox.Text
				$alias = $aliasTextBox.Text
				$progressBar1.Value = 30
				Set-Mailbox $mailbox -EmailAddresses @{Add= $alias}
				$progressBar1.Value = 50
				Write-Host "Added $alias to $mailbox."
				$progressBar1.Value = 80
				CheckForErrors
				OperationComplete
			}
			Default {
				Write-Host "An error seems to have occurred."
				CheckForErrors
			}
		}
	}
	function OnOpenTemplateButtonClick {
		$progressBar1.Value = 10
		Invoke-Item ".\Templates\Add-EmailAlias.csv"
		$progressBar1.Value = 100
		CheckForErrors
		$progressBar1.Value = 0
	}
	function OnAddAliasBulkButtonClick {
		Import-Csv ".\Templates\Add-EmailAlias.csv" | ForEach-Object {
			$progressBar1.Value = 20
			$mailbox = $_.Mailbox
			$alias = $_.Alias
			$progressBar1.Value = 50
			Set-Mailbox $mailbox -EmailAddresses @{Add= $alias}
			Write-Host "Added $alias to $mailbox."
			$progressBar1.Value = 80
		}
		CheckForErrors
		OperationComplete
	}
	function OnIncrementalCheckBoxChecked {
		if ($incrementalCheckBox.Checked -eq $true) {
			$numericUpDown1.Enabled = $true
			$addAliasButton.Text = "Add Aliases"
		} elseif ($incrementalCheckBox.Checked -eq $false) {
			$numericUpDown1.Enabled = $false
			$addAliasButton.Text = "Add Alias"
		}
	}
	function OnGetAliasButtonClick {
		Write-Host "GetAliasButton clicked."
		$progressBar1.Value = 10
		$infoTextBox.Text = Get-Mailbox $mailboxTextBox.Text | Select-Object -ExpandProperty emailaddresses
		$progressBar1.Value = 80
		CheckForErrors
		$progressBar1.Value = 0
	}
	function OnCopyButtonClick {
		Write-Host "CopyButton clicked."
		$progressBar1.Value = 10
		Get-Mailbox $mailboxTextBox.Text | Select-Object -ExpandProperty emailaddresses | Set-Clipboard
		$progressBar1.Value = 80
		CheckForErrors
		OperationComplete
	}

	$emailAliasForm = New-Object System.Windows.Forms.Form

	$groupBox1 = New-Object System.Windows.Forms.GroupBox
	$addAliasButton = New-Object System.Windows.Forms.Button
	$aliasLabel = New-Object System.Windows.Forms.Label
	$aliasTextBox = New-Object System.Windows.Forms.TextBox
	$mailboxLabel = New-Object System.Windows.Forms.Label
	$mailboxTextBox = New-Object System.Windows.Forms.TextBox
	$groupBox2 = New-Object System.Windows.Forms.GroupBox
	$addAliasBulkButton = New-Object System.Windows.Forms.Button
	$openTemplateButton = New-Object System.Windows.Forms.Button
	$groupBox3 = New-Object System.Windows.Forms.GroupBox
	$getAliasButton = New-Object System.Windows.Forms.Button
	$infoTextBox = New-Object System.Windows.Forms.TextBox
	$copyButton = New-Object System.Windows.Forms.Button
	$incrementalCheckBox = New-Object System.Windows.Forms.CheckBox
	$numericUpDown1 = New-Object System.Windows.Forms.NumericUpDown
	#
	# groupBox1
	#
	$groupBox1.Controls.Add($numericUpDown1)
	$groupBox1.Controls.Add($incrementalCheckBox)
	$groupBox1.Controls.Add($addAliasButton)
	$groupBox1.Controls.Add($aliasLabel)
	$groupBox1.Controls.Add($aliasTextBox)
	$groupBox1.Controls.Add($mailboxLabel)
	$groupBox1.Controls.Add($mailboxTextBox)
	$groupBox1.Location = New-Object System.Drawing.Point(12, 12)
	$groupBox1.Name = "groupBox1"
	$groupBox1.Size = New-Object System.Drawing.Size(260, 147)
	$groupBox1.TabIndex = 0
	$groupBox1.TabStop = $false
	$groupBox1.Text = "Single"
	#
	# addAliasButton
	#
	$addAliasButton.Location = New-Object System.Drawing.Point(6, 99)
	$addAliasButton.Name = "addAliasButton"
	$addAliasButton.Size = New-Object System.Drawing.Size(248, 23)
	$addAliasButton.TabIndex = 7
	$addAliasButton.Text = "Add Alias"
	$addAliasButton.UseVisualStyleBackColor = $true
	$addAliasButton.Add_Click({OnAddAliasButtonClick})
	#
	# aliasLabel
	#
	$aliasLabel.AutoSize = $true
	$aliasLabel.Location = New-Object System.Drawing.Point(6, 48)
	$aliasLabel.Name = "aliasLabel"
	$aliasLabel.Size = New-Object System.Drawing.Size(32, 13)
	$aliasLabel.TabIndex = 3
	$aliasLabel.Text = "Alias:"
	#
	# aliasTextBox
	#
	$aliasTextBox.Location = New-Object System.Drawing.Point(58, 45)
	$aliasTextBox.Name = "aliasTextBox"
	$aliasTextBox.Size = New-Object System.Drawing.Size(196, 20)
	$aliasTextBox.TabIndex = 4
	#
	# mailboxLabel
	#
	$mailboxLabel.AutoSize = $true
	$mailboxLabel.Location = New-Object System.Drawing.Point(6, 22)
	$mailboxLabel.Name = "mailboxLabel"
	$mailboxLabel.Size = New-Object System.Drawing.Size(46, 13)
	$mailboxLabel.TabIndex = 1
	$mailboxLabel.Text = "Mailbox:"
	#
	# mailboxTextBox
	#
	$mailboxTextBox.Location = New-Object System.Drawing.Point(58, 19)
	$mailboxTextBox.Name = "mailboxTextBox"
	$mailboxTextBox.Size = New-Object System.Drawing.Size(196, 20)
	$mailboxTextBox.TabIndex = 2
	#
	# groupBox2
	#
	$groupBox2.Controls.Add($addAliasBulkButton)
	$groupBox2.Controls.Add($openTemplateButton)
	$groupBox2.Location = New-Object System.Drawing.Point(12, 165)
	$groupBox2.Name = "groupBox2"
	$groupBox2.Size = New-Object System.Drawing.Size(260, 77)
	$groupBox2.TabIndex = 8
	$groupBox2.TabStop = $false
	$groupBox2.Text = "Bulk"
	#
	# addAliasBulkButton
	#
	$addAliasBulkButton.Location = New-Object System.Drawing.Point(6, 48)
	$addAliasBulkButton.Name = "addAliasBulkButton"
	$addAliasBulkButton.Size = New-Object System.Drawing.Size(248, 23)
	$addAliasBulkButton.TabIndex = 10
	$addAliasBulkButton.Text = "Add Aliases"
	$addAliasBulkButton.UseVisualStyleBackColor = $true
	$addAliasBulkButton.Add_Click({OnAddAliasBulkButtonClick})
	#
	# openTemplateButton
	#
	$openTemplateButton.Location = New-Object System.Drawing.Point(6, 19)
	$openTemplateButton.Name = "openTemplateButton"
	$openTemplateButton.Size = New-Object System.Drawing.Size(248, 23)
	$openTemplateButton.TabIndex = 9
	$openTemplateButton.Text = "Open Template"
	$openTemplateButton.UseVisualStyleBackColor = $true
	$openTemplateButton.Add_Click({OnOpenTemplateButtonClick})
	#
	# groupBox3
	#
	$groupBox3.Controls.Add($copyButton)
	$groupBox3.Controls.Add($infoTextBox)
	$groupBox3.Controls.Add($getAliasButton)
	$groupBox3.Location = New-Object System.Drawing.Point(278, 12)
	$groupBox3.Name = "groupBox3"
	$groupBox3.Size = New-Object System.Drawing.Size(260, 230)
	$groupBox3.TabIndex = 11
	$groupBox3.TabStop = $false
	$groupBox3.Text = "Info"
	#
	# getAliasButton
	#
	$getAliasButton.Location = New-Object System.Drawing.Point(6, 19)
	$getAliasButton.Name = "getAliasButton"
	$getAliasButton.Size = New-Object System.Drawing.Size(248, 23)
	$getAliasButton.TabIndex = 12
	$getAliasButton.Text = "Get Current Aliases"
	$getAliasButton.UseVisualStyleBackColor = $true
	$getAliasButton.Add_Click({OnGetAliasButtonClick})
	#
	# infoTextBox
	#
	$infoTextBox.Location = New-Object System.Drawing.Point(6, 48)
	$infoTextBox.Multiline = $true
	$infoTextBox.Name = "infoTextBox"
	$infoTextBox.ReadOnly = $true
	$infoTextBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
	$infoTextBox.Size = New-Object System.Drawing.Size(248, 147)
	$infoTextBox.TabIndex = 13
	#
	# copyButton
	#
	$copyButton.Location = New-Object System.Drawing.Point(6, 201)
	$copyButton.Name = "copyButton"
	$copyButton.Size = New-Object System.Drawing.Size(248, 23)
	$copyButton.TabIndex = 14
	$copyButton.Text = "Copy to Clipboard"
	$copyButton.UseVisualStyleBackColor = $true
	$copyButton.Add_Click({OnCopyButtonClick})
	#
	# incrementalCheckBox
	#
	$incrementalCheckBox.AutoSize = $true
	$incrementalCheckBox.Location = New-Object System.Drawing.Point(9, 74)
	$incrementalCheckBox.Name = "incrementalCheckBox"
	$incrementalCheckBox.Size = New-Object System.Drawing.Size(146, 17)
	$incrementalCheckBox.TabIndex = 5
	$incrementalCheckBox.Text = "Create Incremental Aliases"
	$incrementalCheckBox.UseVisualStyleBackColor = $true
	$incrementalCheckBox.Add_CheckedChanged({OnIncrementalCheckBoxChecked})
	#
	# numericUpDown1
	#
	$numericUpDown1.Enabled = $false
	$numericUpDown1.Location = New-Object System.Drawing.Point(166, 73)
	$numericUpDown1.Maximum = 1000
	#$numericUpDown1.Maximum = New-Object decimal(@(
	#1000,
	#0,
	#0,
	#0))
	$numericUpDown1.Name = "numericUpDown1"
	$numericUpDown1.Size = New-Object System.Drawing.Size(88, 20)
	$numericUpDown1.TabIndex = 6
	#
	# emailAliasForm
	#
	$emailAliasForm.ClientSize = New-Object System.Drawing.Size(550, 254)
	$emailAliasForm.Controls.Add($groupBox3)
	$emailAliasForm.Controls.Add($groupBox1)
	$emailAliasForm.Controls.Add($groupBox2)
	$emailAliasForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$emailAliasForm.MaximizeBox = $false
	$emailAliasForm.MinimizeBox = $false
	$emailAliasForm.Name = "emailAliasForm"
	$emailAliasForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$emailAliasForm.Text = "Add-EmailAlias"

	$emailAliasForm.Add_Shown({$emailAliasForm.Activate()})

	$progressBar1.Value = 100
	Write-Host "Loaded EmailAliasForm."
	$progressBar1.Value = 0

	$emailAliasForm.ShowDialog()
	$emailAliasForm.Dispose()

	Stop-Transcript
}
function Add-MailboxMember {
	$progressBar1.Value = 10
	$Script:mailboxMemberMode = 0
	if ($selectedScript -eq "Add-MailboxMember") {
		Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Add-MailboxMember.txt"
		Write-Host "Running Add-MailboxMember script..."
		$Script:mailboxMemberMode = 0
	} elseif ($selectedScript -eq "Remove-MailboxMember") {
		Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Remove-MailboxMember.txt"
		Write-Host "Running Remove-MailboxMember script..."
		$Script:mailboxMemberMode = 1
	}
	$progressBar1.Value = 20
	function OnRadioButtonSelect {
		if ($addMemberRadioButton.Checked -eq $true) {
			$scriptForm1.Text = "Add-MailboxMember"
			$memberButton.Text = "Add Member"
			$bulkMembersButton.Text = "Add Members"
			$Script:mailboxMemberMode = 0
		}
		elseif ($removeMemberRadioButton.Checked -eq $true) {
			$scriptForm1.Text = "Remove-MailboxMember"
			$memberButton.Text = "Remove Member"
			$bulkMembersButton.Text = "Remove Members"
			$Script:mailboxMemberMode = 1
		}
		Write-Host "Mode = $mailboxMemberMode"
		CheckForErrors
	}
	function OnMemberButtonClick {
		if ($mailboxMemberMode -eq 0) {
			$mailbox = $mailboxInputBox.Text
			$member = $memberInputBox.Text
			$progressBar1.Value = 10
			Add-MailboxPermission -Identity $mailbox -User $member -AccessRights FullAccess -InheritanceType All -AutoMapping $true
			$progressBar1.Value = 50
			Add-RecipientPermission -Identity $mailbox -Trustee $member -AccessRights SendAs -Confirm:$false
			$progressBar1.Value = 80
			Write-Host "Added $member to $mailbox." -ForegroundColor Cyan
		} elseif ($mailboxMemberMode -eq 1) {
			$mailbox = $mailboxInputBox.Text
			$member = $memberInputBox.Text
			$progressBar1.Value = 10
			Remove-MailboxPermission -Identity $mailbox -User $member -AccessRights FullAccess -InheritanceType All -Confirm:$false
			$progressBar1.Value = 50
			Remove-RecipientPermission -Identity $mailbox -Trustee $member -AccessRights SendAs -Confirm:$false
			$progressBar1.Value = 90
			Write-Host "Removed $member from $mailbox." -ForegroundColor Cyan
		}
		CheckForErrors
		OperationComplete
	}
	function OnFullAccessButtonClick {
		if ($mailboxMemberMode -eq 0) {
			$mailbox = $mailboxInputBox.Text
			$member = $memberInputBox.Text
			$progressBar1.Value = 10
			Add-MailboxPermission -Identity $mailbox -User $member -AccessRights FullAccess -InheritanceType All -AutoMapping $true
			$progressBar1.Value = 50
			Write-Host "Added Read and Manage permission for $member to $mailbox." -ForegroundColor Cyan
		} elseif ($mailboxMemberMode -eq 1) {
			$mailbox = $mailboxInputBox.Text
			$member = $memberInputBox.Text
			$progressBar1.Value = 10
			Remove-MailboxPermission -Identity $mailbox -User $member -AccessRights FullAccess -InheritanceType All -Confirm:$false
			$progressBar1.Value = 50
			Write-Host "Removed FullAccess permission for $member from $mailbox." -ForegroundColor Cyan
		}
		CheckForErrors
		OperationComplete
	}
	function OnSendOnBehalfButtonClick {
		if ($mailboxMemberMode -eq 0) {
			$mailbox = $mailboxInputBox.Text
			$member = $memberInputBox.Text
			$progressBar1.Value = 10
			Set-Mailbox -Identity $mailbox -GrantSendOnBehalfTo @{Add=$member}
			$progressBar1.Value = 50
			Write-Host "Added SendOnBehalf permission for $member to $mailbox" -ForegroundColor Cyan
		} elseif ($mailboxMemberMode -eq 1) {
			$mailbox = $mailboxInputBox.Text
			$member = $memberInputBox.Text
			$progressBar1.Value = 10
			Set-Mailbox -Identity $mailbox -GrantSendOnBehalfTo @{Remove=$member}
			$progressBar1.Value = 50
			Write-Host "Removed SendOnBehalf permission for $member from $mailbox." -ForegroundColor Cyan
		}
		CheckForErrors
		OperationComplete
	}
	function OnSendAsButtonClick {
		if ($mailboxMemberMode -eq 0) {
			$mailbox = $mailboxInputBox.Text
			$member = $memberInputBox.Text
			$progressBar1.Value = 10
			Add-RecipientPermission -Identity $mailbox -Trustee $member -AccessRights SendAs -Confirm:$false
			$progressBar1.Value = 50
			Write-Host "Added SendAs permission for $member to $mailbox." -ForegroundColor Cyan
		} elseif ($mailboxMemberMode = 1) {
			$mailbox = $mailboxInputBox.Text
			$member = $memberInputBox.Text
			$progressBar1.Value = 10
			Remove-RecipientPermission -Identity $mailbox -Trustee $member -AccessRights SendAs -Confirm:$false
			$progressBar1.Value = 50
			Write-Host "Removed SendAs permission for $member from $mailbox." -ForegroundColor Cyan
		}
		CheckForErrors
		OperationComplete
	}
	function OnOpenTemplateButtonClick {
		if ($mailboxMemberMode -eq 0) {
			Write-Host "Open template button clicked."
			$progressBar1.Value = 10
			Invoke-Item ".\Templates\Add-MailboxMember.csv"
			$progressBar1.Value = 0
		} elseif ($mailboxMemberMode -eq 1) {
			Write-Host "Open template button clicked."
			$progressBar1.Value = 10
			Invoke-Item ".\Templates\Remove-MailboxMember.csv"
			$progressBar1.Value = 0
		}
		CheckForErrors
	}
	function OnBulkMembersButtonClick {
		$progressBar1.Value = 10
		if ($mailboxMemberMode -eq 0) {
			Import-Csv ".\Templates\Add-MailboxMember.csv" | ForEach-Object {
				$member = $_.Member
				$mailbox = $_.Mailbox
				$progressBar1.Value = 20
				Add-MailboxPermission -Identity $mailbox -User $member -AccessRights FullAccess -InheritanceType All -AutoMapping $true
				$progressBar1.Value = 50
				Add-RecipientPermission -Identity $mailbox -Trustee $member -AccessRights SendAs -Confirm:$false
				$progressBar1.Value = 80
				Write-Host "Added $member to $mailbox." -ForegroundColor Cyan
			}
		} elseif ($mailboxMemberMode -eq 1) {
			Import-Csv ".\Templates\Remove-MailboxMember.csv" | ForEach-Object {
				$member = $_.Member
				$mailbox = $_.Mailbox
				$progressBar1.Value = 20
				Remove-MailboxPermission -Identity $mailbox -User $member -AccessRights FullAccess -InheritanceType All -Confirm:$false
				$progressBar1.Value = 50
				Remove-RecipientPermission -Identity $mailbox -Trustee $member -AccessRights SendAs -Confirm:$false
				$progressBar1.Value = 80
				Write-Host "Removed $member from $mailbox." -ForegroundColor Cyan
			}
		}
		CheckForErrors
		OperationComplete
	}

	$scriptForm1 = New-Object System.Windows.Forms.Form

	$sendAsButton = New-Object System.Windows.Forms.Button
	$sendOnBehalfButton = New-Object System.Windows.Forms.Button
	$fullAccessButton = New-Object System.Windows.Forms.Button
	$memberLabel = New-Object System.Windows.Forms.Label
	$memberButton = New-Object System.Windows.Forms.Button
	$mailboxLabel = New-Object System.Windows.Forms.Label
	$mailboxInputBox = New-Object System.Windows.Forms.TextBox
	$memberInputBox = New-Object System.Windows.Forms.TextBox
	$groupBox1 = New-Object System.Windows.Forms.GroupBox
	$addMemberRadioButton = New-Object System.Windows.Forms.RadioButton
	$removeMemberRadioButton = New-Object System.Windows.Forms.RadioButton
	$bulkGroupBox = New-Object System.Windows.Forms.GroupBox
	$openTemplateButton = New-Object System.Windows.Forms.Button
	$bulkMembersButton = New-Object System.Windows.Forms.Button
	#
	# sendAsButton
	#
	$sendAsButton.Location = New-Object System.Drawing.Point(202, 167)
	$sendAsButton.Name = "sendAsButton"
	$sendAsButton.Size = New-Object System.Drawing.Size(90, 23)
	$sendAsButton.TabIndex = 7
	$sendAsButton.Text = "SendAs"
	$sendAsButton.UseVisualStyleBackColor = $true
	$sendAsButton.Add_Click({OnSendAsButtonClick})
	#
	# sendOnBehalfButton
	#
	$sendOnBehalfButton.Location = New-Object System.Drawing.Point(106, 167)
	$sendOnBehalfButton.Name = "sendOnBehalfButton"
	$sendOnBehalfButton.Size = New-Object System.Drawing.Size(90, 23)
	$sendOnBehalfButton.TabIndex = 6
	$sendOnBehalfButton.Text = "SendOnBehalf"
	$sendOnBehalfButton.UseVisualStyleBackColor = $true
	$sendOnBehalfButton.UseWaitCursor = $true
	$sendOnBehalfButton.Add_Click({OnSendOnBehalfButtonClick})
	#
	# fullAccessButton
	#
	$fullAccessButton.Location = New-Object System.Drawing.Point(12, 167)
	$fullAccessButton.Name = "fullAccessButton"
	$fullAccessButton.Size = New-Object System.Drawing.Size(88, 23)
	$fullAccessButton.TabIndex = 5
	$fullAccessButton.Text = "FullAccess"
	$fullAccessButton.UseVisualStyleBackColor = $true
	$fullAccessButton.Add_Click({OnFullAccessButtonClick})
	#
	# memberLabel
	#
	$memberLabel.AutoSize = $true
	$memberLabel.Location = New-Object System.Drawing.Point(9, 15)
	$memberLabel.Name = "memberLabel"
	$memberLabel.Size = New-Object System.Drawing.Size(48, 13)
	$memberLabel.TabIndex = 0
	$memberLabel.Text = "Member:"
	#
	# memberButton
	#
	$memberButton.Location = New-Object System.Drawing.Point(12, 138)
	$memberButton.Name = "memberButton"
	$memberButton.Size = New-Object System.Drawing.Size(280, 23)
	$memberButton.TabIndex = 4
	$memberButton.Text = "Add Member"
	$memberButton.UseVisualStyleBackColor = $true
	$memberButton.Add_Click({OnMemberButtonClick})
	#
	# mailboxLabel
	#
	$mailboxLabel.AutoSize = $true
	$mailboxLabel.Location = New-Object System.Drawing.Point(9, 41)
	$mailboxLabel.Name = "mailboxLabel"
	$mailboxLabel.Size = New-Object System.Drawing.Size(46, 13)
	$mailboxLabel.TabIndex = 1
	$mailboxLabel.Text = "Mailbox:"
	#
	# mailboxInputBox
	#
	$mailboxInputBox.Location = New-Object System.Drawing.Point(63, 38)
	$mailboxInputBox.Name = "mailboxInputBox"
	$mailboxInputBox.Size = New-Object System.Drawing.Size(229, 20)
	$mailboxInputBox.TabIndex = 1
	#
	# memberInputBox
	#
	$memberInputBox.Location = New-Object System.Drawing.Point(63, 12)
	$memberInputBox.Name = "memberInputBox"
	$memberInputBox.Size = New-Object System.Drawing.Size(229, 20)
	$memberInputBox.TabIndex = 0
	#
	# groupBox1
	#
	$groupBox1.Controls.Add($removeMemberRadioButton)
	$groupBox1.Controls.Add($addMemberRadioButton)
	$groupBox1.Location = New-Object System.Drawing.Point(12, 64)
	$groupBox1.Name = "groupBox1"
	$groupBox1.Size = New-Object System.Drawing.Size(280, 68)
	$groupBox1.TabIndex = 2
	$groupBox1.TabStop = $false
	$groupBox1.Text = "Add/Remove"
	#
	# addMemberRadioButton
	#
	$addMemberRadioButton.AutoSize = $true
	$addMemberRadioButton.Location = New-Object System.Drawing.Point(6, 19)
	$addMemberRadioButton.Name = "addMemberRadioButton"
	$addMemberRadioButton.Size = New-Object System.Drawing.Size(85, 17)
	$addMemberRadioButton.TabIndex = 2
	$addMemberRadioButton.TabStop = $true
	$addMemberRadioButton.Text = "Add Member"
	$addMemberRadioButton.UseVisualStyleBackColor = $true
	$addMemberRadioButton.Add_CheckedChanged({OnRadioButtonSelect})
	#
	# removeMemberRadioButton
	#
	$removeMemberRadioButton.AutoSize = $true
	$removeMemberRadioButton.Location = New-Object System.Drawing.Point(6, 42)
	$removeMemberRadioButton.Name = "removeMemberRadioButton"
	$removeMemberRadioButton.Size = New-Object System.Drawing.Size(106, 17)
	$removeMemberRadioButton.TabIndex = 3
	$removeMemberRadioButton.Text = "Remove Member"
	$removeMemberRadioButton.UseVisualStyleBackColor = $true
	$removeMemberRadioButton.Add_CheckedChanged({OnRadioButtonSelect})
	#
	# bulkGroupBox
	#
	$bulkGroupBox.Controls.Add($bulkMembersButton)
	$bulkGroupBox.Controls.Add($openTemplateButton)
	$bulkGroupBox.Location = New-Object System.Drawing.Point(12, 196)
	$bulkGroupBox.Name = "bulkGroupBox"
	$bulkGroupBox.Size = New-Object System.Drawing.Size(280, 77)
	$bulkGroupBox.TabIndex = 8
	$bulkGroupBox.TabStop = $false
	$bulkGroupBox.Text = "Bulk"
	#
	# openTemplateButton
	#
	$openTemplateButton.Location = New-Object System.Drawing.Point(6, 19)
	$openTemplateButton.Name = "openTemplateButton"
	$openTemplateButton.Size = New-Object System.Drawing.Size(268, 23)
	$openTemplateButton.TabIndex = 8
	$openTemplateButton.Text = "Open Template"
	$openTemplateButton.UseVisualStyleBackColor = $true
	$openTemplateButton.Add_Click({OnOpenTemplateButtonClick})
	#
	# bulkMembersButton
	#
	$bulkMembersButton.Location = New-Object System.Drawing.Point(6, 48)
	$bulkMembersButton.Name = "bulkMembersButton"
	$bulkMembersButton.Size = New-Object System.Drawing.Size(268, 23)
	$bulkMembersButton.TabIndex = 9
	$bulkMembersButton.Text = "Add Members"
	$bulkMembersButton.UseVisualStyleBackColor = $true
	$bulkMembersButton.Add_Click({OnBulkMembersButtonClick})
	#
	# scriptForm1
	#
	$scriptForm1.ClientSize = New-Object System.Drawing.Size(304, 285)
	$scriptForm1.Controls.Add($bulkGroupBox)
	$scriptForm1.Controls.Add($groupBox1)
	$scriptForm1.Controls.Add($sendAsButton)
	$scriptForm1.Controls.Add($sendOnBehalfButton)
	$scriptForm1.Controls.Add($fullAccessButton)
	$scriptForm1.Controls.Add($memberLabel)
	$scriptForm1.Controls.Add($memberButton)
	$scriptForm1.Controls.Add($mailboxLabel)
	$scriptForm1.Controls.Add($mailboxInputBox)
	$scriptForm1.Controls.Add($memberInputBox)
	$scriptForm1.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$scriptForm1.MaximizeBox = $false
	$scriptForm1.MinimizeBox = $false
	$scriptForm1.Name = "scriptForm1"
	$scriptForm1.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$scriptForm1.Add_Shown({$scriptForm1.Activate()})

	if ($mailboxMemberMode -eq 0) {
		$scriptForm1.Text = "Add-MailboxMember"
		$memberButton.Text = "Add Member"
		$bulkMembersButton.Text = "Add Members"
		$addMemberRadioButton.Checked = $true
	} elseif ($mailboxMemberMode -eq 1) {
		$scriptForm1.Text = "Remove-MailboxMember"
		$memberButton.Text = "Remove Member"
		$bulkMembersButton.Text = "Remove Members"
		$removeMemberRadioButton.Checked = $true
	}

	Write-Host "Loaded ScriptForm1."
	$progressBar1.Value = 0

	$scriptForm1.ShowDialog()
	$scriptForm1.Dispose()

	Stop-Transcript
}
function Add-TrustedSender {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Add-TrustedSender.txt"
	Write-Host "Running Add-TrustedSender script..."
	$progressBar1.Value = 10
	function OnTrustedSenderButtonClick {
		$trustedSender = $trustedSenderInputBox.Text
		$progressBar1.Value = 10
		Get-Mailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited | ForEach-Object {
			$progressBar1.Value = 30
			Set-MailboxJunkEmailConfiguration $_.Name -TrustedSendersAndDomains @{Add=$trustedSender}
			$progressBar1.Value = 80
			Write-Host "Configured " + $_.Name
		}
		Write-Host "Finished configuring mailboxes."
		CheckForErrors
		OperationComplete
	}

	$ScriptForm5 = New-Object System.Windows.Forms.Form

	$trustedSenderLabel = New-Object System.Windows.Forms.Label
	$trustedSenderInputBox = New-Object System.Windows.Forms.TextBox
	$trustedSenderButton = New-Object System.Windows.Forms.Button
	#
	# trustedSenderLabel
	#
	$trustedSenderLabel.AutoSize = $true
	$trustedSenderLabel.Location = New-Object System.Drawing.Point(12, 16)
	$trustedSenderLabel.Name = "trustedSenderLabel"
	$trustedSenderLabel.Size = New-Object System.Drawing.Size(86, 13)
	$trustedSenderLabel.TabIndex = 0
	$trustedSenderLabel.Text = "Email or Domain:"
	#
	# trustedSenderInputBox
	#
	$trustedSenderInputBox.Location = New-Object System.Drawing.Point(105, 13)
	$trustedSenderInputBox.Name = "trustedSenderInputBox"
	$trustedSenderInputBox.Size = New-Object System.Drawing.Size(212, 20)
	$trustedSenderInputBox.TabIndex = 1
	#
	# trustedSenderButton
	#
	$trustedSenderButton.Location = New-Object System.Drawing.Point(12, 40)
	$trustedSenderButton.Name = "trustedSenderButton"
	$trustedSenderButton.Size = New-Object System.Drawing.Size(305, 23)
	$trustedSenderButton.TabIndex = 2
	$trustedSenderButton.Text = "Add Trusted Sender"
	$trustedSenderButton.UseVisualStyleBackColor = $true
	$trustedSenderButton.Add_Click({OnTrustedSenderButtonClick})
	#
	# ScriptForm5
	#
	$ScriptForm5.AcceptButton = $trustedSenderButton
	$ScriptForm5.ClientSize = New-Object System.Drawing.Size(329, 75)
	$ScriptForm5.Controls.Add($trustedSenderButton)
	$ScriptForm5.Controls.Add($trustedSenderInputBox)
	$ScriptForm5.Controls.Add($trustedSenderLabel)
	$ScriptForm5.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$ScriptForm5.MaximizeBox = $false
	$ScriptForm5.MinimizeBox = $false
	$ScriptForm5.Name = "ScriptForm5"
	$ScriptForm5.Text = "Add-TrustedSender"
	$ScriptForm5.StartPosition = "CenterParent"
	$ScriptForm5.Add_Shown({$ScriptForm5.Activate()})

	Write-Host "Loaded ScriptForm5"
	$progressBar1.Value = 0

	$ScriptForm5.ShowDialog()
	$ScriptForm5.Dispose()

	Stop-Transcript
}
function Add-UnifiedGroupMember {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Add-UnifiedGroupMember.txt"
	Write-Host "Running Add-UnifiedGroupMember script..."
	$progressBar1.Value = 10
	function OnAddMemberButtonClick {
		Write-Host "AddMember button clicked."
		$progressBar1.Value = 20
		$member = $memberInputBox.Text
		$group = $groupInputBox.Text
		$progressBar1.Value = 30
		Add-UnifiedGroupLinks -Identity $group -LinkType Members -Links $member
		Write-Host "Adding $member..."
		$progressBar1.Value = 80
		CheckForErrors
		OperationComplete
	}
	function OnOpenTemplateButtonClick {
		Write-Host "OpenTemplate button clicked."
		$progressBar1.Value = 10
		Invoke-Item ".\Templates\Add-UnifiedGroupMember.csv"
		$progressBar1.Value = 100
		CheckForErrors
		$progressBar1.Value = 0
	}
	function OnAddBulkMembersButtonClick {
		Write-Host "AddBulkMembers button clicked."
		$progressBar1.Value = 10
		Import-Csv ".\Templates\Add-UnifiedGroupMember.csv" | ForEach-Object {
			$progressBar1.Value = 30
			$member = $_.Member
			$group = $_.Group
			Add-UnifiedGroupLinks -Identity $group -LinkType Members -Links $member
			Write-Host "Adding $member ..."
			$progressBar1.Value = 80
		}
		CheckForErrors
		OperationComplete
	}

	$scriptForm8 = New-Object System.Windows.Forms.Form

	$groupBox1 = New-Object System.Windows.Forms.GroupBox
	$memberInputBox = New-Object System.Windows.Forms.TextBox
	$label1 = New-Object System.Windows.Forms.Label
	$groupInputBox = New-Object System.Windows.Forms.TextBox
	$label2 = New-Object System.Windows.Forms.Label
	$addMemberButton = New-Object System.Windows.Forms.Button
	$groupBox2 = New-Object System.Windows.Forms.GroupBox
	$openTemplateButton = New-Object System.Windows.Forms.Button
	$addBulkMembersButton = New-Object System.Windows.Forms.Button
	#
	# groupBox1
	#
	$groupBox1.Controls.Add($addMemberButton)
	$groupBox1.Controls.Add($label2)
	$groupBox1.Controls.Add($groupInputBox)
	$groupBox1.Controls.Add($label1)
	$groupBox1.Controls.Add($memberInputBox)
	$groupBox1.Location = New-Object System.Drawing.Point(12, 12)
	$groupBox1.Name = "groupBox1"
	$groupBox1.Size = New-Object System.Drawing.Size(266, 100)
	$groupBox1.TabIndex = 0
	$groupBox1.TabStop = $false
	$groupBox1.Text = "Single"
	#
	# textBox1
	#
	$memberInputBox.Location = New-Object System.Drawing.Point(60, 19)
	$memberInputBox.Name = "textBox1"
	$memberInputBox.Size = New-Object System.Drawing.Size(200, 20)
	$memberInputBox.TabIndex = 0
	#
	# label1
	#
	$label1.AutoSize = $true
	$label1.Location = New-Object System.Drawing.Point(6, 22)
	$label1.Name = "label1"
	$label1.Size = New-Object System.Drawing.Size(48, 13)
	$label1.TabIndex = 0
	$label1.Text = "Member:"
	#
	# textBox2
	#
	$groupInputBox.Location = New-Object System.Drawing.Point(60, 45)
	$groupInputBox.Name = "textBox2"
	$groupInputBox.Size = New-Object System.Drawing.Size(200, 20)
	$groupInputBox.TabIndex = 1
	#
	# label2
	#
	$label2.AutoSize = $true
	$label2.Location = New-Object System.Drawing.Point(6, 48)
	$label2.Name = "label2"
	$label2.Size = New-Object System.Drawing.Size(39, 13)
	$label2.TabIndex = 1
	$label2.Text = "Group:"
	#
	# addMemberButton
	#
	$addMemberButton.Location = New-Object System.Drawing.Point(6, 71)
	$addMemberButton.Name = "addMemberButton"
	$addMemberButton.Size = New-Object System.Drawing.Size(254, 23)
	$addMemberButton.TabIndex = 2
	$addMemberButton.Text = "Add Member"
	$addMemberButton.UseVisualStyleBackColor = $true
	$addMemberButton.Add_Click({OnAddMemberButtonClick})
	#
	# groupBox2
	#
	$groupBox2.Controls.Add($addBulkMembersButton)
	$groupBox2.Controls.Add($openTemplateButton)
	$groupBox2.Location = New-Object System.Drawing.Point(12, 118)
	$groupBox2.Name = "groupBox2"
	$groupBox2.Size = New-Object System.Drawing.Size(266, 77)
	$groupBox2.TabIndex = 3
	$groupBox2.TabStop = $false
	$groupBox2.Text = "Bulk"
	#
	# openTemplateButton
	#
	$openTemplateButton.Location = New-Object System.Drawing.Point(6, 19)
	$openTemplateButton.Name = "openTemplateButton"
	$openTemplateButton.Size = New-Object System.Drawing.Size(254, 23)
	$openTemplateButton.TabIndex = 3
	$openTemplateButton.Text = "Open Template"
	$openTemplateButton.UseVisualStyleBackColor = $true
	$openTemplateButton.Add_Click({OnOpenTemplateButtonClick})
	#
	# addBulkMembersButton
	#
	$addBulkMembersButton.Location = New-Object System.Drawing.Point(6, 48)
	$addBulkMembersButton.Name = "addBulkMembersButton"
	$addBulkMembersButton.Size = New-Object System.Drawing.Size(254, 23)
	$addBulkMembersButton.TabIndex = 4
	$addBulkMembersButton.Text = "Add Members"
	$addBulkMembersButton.UseVisualStyleBackColor = $true
	$addBulkMembersButton.Add_Click({OnAddBulkMembersButtonClick})
	#
	# scriptForm8
	#
	$scriptForm8.ClientSize = New-Object System.Drawing.Size(290, 207)
	$scriptForm8.Controls.Add($groupBox2)
	$scriptForm8.Controls.Add($groupBox1)
	$scriptForm8.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$scriptForm8.HelpButton = $false
	$scriptForm8.MaximizeBox = $false
	$scriptForm8.MinimizeBox = $false
	$scriptForm8.Name = "scriptForm8"
	$scriptForm8.ShowIcon = $false
	$scriptForm8.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$scriptForm8.Text = "Add-UnifiedGroupMember"
	$scriptForm8.Add_Shown({$scriptForm8.Activate()})

	Write-Host "Loaded ScriptForm8."
	$progressBar1.Value = 0

	$scriptForm8.ShowDialog()
	$scriptForm8.Dispose()

	Stop-Transcript
}
function Block-User {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Block-User.txt"
	Write-Host "Running Block-User script..."
	$progressBar1.Value = 10
	function OnBlockButtonClick {
		Write-Host "Block button clicked."
		$progressBar1.Value = 10
		if ($adCheckBox.Checked -eq $true) {
			Import-Module ActiveDirectory
			$user = $adNameInputBox.Text
			$progressBar1.Value = 20
			$samAccountName = $adNameInputBox.Text
			Disable-ADAccount -Identity $samAccountName
			Write-Host "Disabled $samAccountName. If there are any erros on this point then $samAccountName may not exist."
			$progressBar1.Value = 30
			CheckForErrors
		}
		if ($emailCheckBox.Checked -eq $true) {
			$user = $emailInputBox.Text
			Set-Mailbox -Identity $user -Type Shared
			Write-Host "`nConverted $user to shared mailbox" -ForegroundColor Cyan
			$progressBar1.Value = 40
			$passwordMethod = Get-MgUserAuthenticationPasswordMethod -UserId $user
			Reset-MgUserAuthenticationMethodPassword -UserId $user -AuthenticationMethodId $passwordMethod.Id
			Write-Host "Reset password for $user" -ForegroundColor Cyan
			$progressBar1.Value = 50
			Revoke-MgUserSignInSession -UserId $user
			Write-Host "Revoked $user's sessions."
			Update-MgUser -UserId $user -AccountEnabled:$false
			Write-Host "Disabled $user account" -ForegroundColor Cyan -NoNewline
			$progressBar1.Value = 60
			$license = Get-MgUserLicenseDetail -UserId $user
			Set-MgUserLicense -UserId $user -RemoveLicenses $license.SkuId -AddLicenses @{}
			Write-Host "Removed licenses from $user" -ForegroundColor Cyan
			$progressBar1.Value = 70
			$phoneMethod = Get-MgUserAuthenticationPhoneMethod -UserId $user
			if ($null -eq $phoneMethod) {
				Write-Host "$user doesn't have a 2FA phone number" -ForegroundColor Cyan
			} else {
				Remove-MgUserAuthenticationPhoneMethod -UserId $user -PhoneAuthenticationMethodId $phoneMethod.Id
				Write-Host "Removed 2FA phone number from $user" -ForegroundColor Cyan
			}
			$progressBar1.Value = 80
			CheckForErrors
			if ($addMembersCheckBox.Checked -eq $true) {
				Write-Host "addMembersCheckBox is checked, loading AddMember form..."
				function OnAddMemberButtonClick {
					$addUser = $addMemberBox.Text
					Add-MailboxPermission -Identity $user -User $addUser -AccessRights FullAccess -InheritanceType All -AutoMapping $true
					Add-RecipientPermission -Identity $user -Trustee $addUser -AccessRights SendAs -Confirm:$false
					Write-Host "Added $addUser to $user" -ForegroundColor Cyan
					$addMemberBox.Text = ""
					CheckForErrors
					OperationComplete
				}
		
				$AddMemberForm = New-Object System.Windows.Forms.Form
		
				$addLabel = New-Object System.Windows.Forms.Label
				$addMemberBox = New-Object System.Windows.Forms.TextBox
				$addMemberButton = New-Object System.Windows.Forms.Button
				#
				# addLabel
				#
				$addLabel.AutoSize = $true
				$addLabel.Location = New-Object System.Drawing.Point(9, 15)
				$addLabel.Name = "addLabel"
				$addLabel.Size = New-Object System.Drawing.Size(37, 13)
				$addLabel.TabIndex = 0
				$addLabel.Text = "Member:"
				#
				# addMemberBox
				#
				$addMemberBox.Location = New-Object System.Drawing.Point(66, 12)
				$addMemberBox.Name = "addMemberBox"
				$addMemberBox.Size = New-Object System.Drawing.Size(199, 20)
				$addMemberBox.TabIndex = 1
				#
				# addMemberButton
				#
				$addMemberButton.Location = New-Object System.Drawing.Point(12, 39)
				$addMemberButton.Name = "addMemberButton"
				$addMemberButton.Size = New-Object System.Drawing.Size(252, 23)
				$addMemberButton.TabIndex = 2
				$addMemberButton.Text = "Add"
				$addMemberButton.UseVisualStyleBackColor = $true
				$addMemberButton.Add_Click({OnAddMemberButtonClick})
				#
				# AddMemberForm
				#
				$AddMemberForm.AcceptButton = $addMemberButton
				$AddMemberForm.ClientSize = New-Object System.Drawing.Size(273, 74)
				$AddMemberForm.Controls.Add($addMemberButton)
				$AddMemberForm.Controls.Add($addMemberBox)
				$AddMemberForm.Controls.Add($addLabel)
				$AddMemberForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
				$AddMemberForm.MaximizeBox = $false
				$AddMemberForm.MinimizeBox = $false
				$AddMemberForm.Name = "AddMemberForm"
				$AddMemberForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
				$AddMemberForm.Text = "Add members to the blocked mailbox."
				Write-Host "Loaded AddMemberForm."
				$AddMemberForm.Add_Shown({$AddMemberForm.Activate()})
				$AddMemberForm.ShowDialog()
				$AddMemberForm.Dispose()
			}
			if ($addAutoReplyCheckBox.Checked -eq $true) {
				Write-Host "addAutoReplyCheckBox is checked, loading AddAutoReply form..."

				function OnConfirmAutoReplyButtonClick {
					Write-Host "ConfirmAutoReplyButton clicked, adding auto-replies..."
					$internalMessage = $internalReplyTextBox.Text
					$externalMessage = $externalReplyTextBox.Text

					if ($useScheduleCheckBox.Checked -eq $true) {
						Write-Host "Use schedule is checked, creating auto-reply with schedule..."
						$startTime = $startDatePicker.Value
						$endTime = $endDatePicker.Value
						Set-MailboxAutoReplyConfiguration -Identity $user -AutoReplyState Scheduled -StartTime $startTime -EndTime $endTime -InternalMessage $internalMessage -ExternalMessage $externalMessage -ExternalAudience All -Confirm:$false
					}
					else {
						Write-Host "Use schedule isn't checked, creating auto-reply..."
						Set-MailboxAutoReplyConfiguration -Identity $user -AutoReplyState Enabled -InternalMessage $internalMessage -ExternalMessage $externalMessage -ExternalAudience All -Confirm:$false
					}
					CheckForErrors
					OperationComplete
					$addAutoReplyForm.Close()
				}

				$addAutoReplyForm = New-Object System.Windows.Forms.Form

				$internalReplyLabel = New-Object System.Windows.Forms.Label
				$internalReplyTextBox = New-Object System.Windows.Forms.TextBox
				$externalReplyTextBox = New-Object System.Windows.Forms.TextBox
				$externalReplyLabel = New-Object System.Windows.Forms.Label
				$matchRepliesCheckBox = New-Object System.Windows.Forms.CheckBox
				$confirmAutoReplyButton = New-Object System.Windows.Forms.Button
				$startDatePicker = New-Object System.Windows.Forms.DateTimePicker
				$useScheduleCheckBox = New-Object System.Windows.Forms.CheckBox
				$endDatePicker = New-Object System.Windows.Forms.DateTimePicker
				#
				# internalReplyLabel
				#
				$internalReplyLabel.AutoSize = $true
				$internalReplyLabel.Location = New-Object System.Drawing.Point(9, 9)
				$internalReplyLabel.Name = "internalReplyLabel"
				$internalReplyLabel.Size = New-Object System.Drawing.Size(100, 13)
				$internalReplyLabel.TabIndex = 0
				$internalReplyLabel.Text = "Internal Auto-Reply:"
				#
				# internalReplyTextBox
				#
				$internalReplyTextBox.Location = New-Object System.Drawing.Point(12, 25)
				$internalReplyTextBox.Multiline = $true
				$internalReplyTextBox.Name = "internalReplyTextBox"
				$internalReplyTextBox.Size = New-Object System.Drawing.Size(175, 224)
				$internalReplyTextBox.TabIndex = 1
				$internalReplyTextBox.Add_TextChanged({
					if ($matchRepliesCheckBox.Checked -eq $true) {$externalReplyTextBox.Text = $internalReplyTextBox.Text}
				})
				#
				# externalReplyTextBox
				#
				$externalReplyTextBox.Location = New-Object System.Drawing.Point(197, 25)
				$externalReplyTextBox.Multiline = $true
				$externalReplyTextBox.Name = "externalReplyTextBox"
				$externalReplyTextBox.Size = New-Object System.Drawing.Size(175, 224)
				$externalReplyTextBox.TabIndex = 3
				$externalReplyTextBox.Add_TextChanged({
					if ($matchRepliesCheckBox.Checked -eq $true) {$internalReplyTextBox.Text = $externalReplyTextBox.Text}
				})
				#
				# externalReplyLabel
				#
				$externalReplyLabel.AutoSize = $true
				$externalReplyLabel.Location = New-Object System.Drawing.Point(194, 9)
				$externalReplyLabel.Name = "externalReplyLabel"
				$externalReplyLabel.Size = New-Object System.Drawing.Size(103, 13)
				$externalReplyLabel.TabIndex = 2
				$externalReplyLabel.Text = "External Auto-Reply:"
				#
				# matchRepliesCheckBox
				#
				$matchRepliesCheckBox.AutoSize = $true
				$matchRepliesCheckBox.Checked = $true
				$matchRepliesCheckBox.CheckState = [System.Windows.Forms.CheckState]::Checked
				$matchRepliesCheckBox.Location = New-Object System.Drawing.Point(12, 258)
				$matchRepliesCheckBox.Name = "matchRepliesCheckBox"
				$matchRepliesCheckBox.Size = New-Object System.Drawing.Size(94, 17)
				$matchRepliesCheckBox.TabIndex = 4
				$matchRepliesCheckBox.Text = "Match Replies"
				$matchRepliesCheckBox.UseVisualStyleBackColor = $true
				#
				# confirmAutoReplyButton
				#
				$confirmAutoReplyButton.Location = New-Object System.Drawing.Point(12, 307)
				$confirmAutoReplyButton.Name = "confirmAutoReplyButton"
				$confirmAutoReplyButton.Size = New-Object System.Drawing.Size(360, 26)
				$confirmAutoReplyButton.TabIndex = 8
				$confirmAutoReplyButton.Text = "Confirm"
				$confirmAutoReplyButton.UseVisualStyleBackColor = $true
				$confirmAutoReplyButton.Add_Click({OnConfirmAutoReplyButtonClick})
				#
				# startDatePicker
				#
				$startDatePicker.Enabled = $false
				$startDatePicker.Location = New-Object System.Drawing.Point(172, 255)
				$startDatePicker.Name = "startDatePicker"
				$startDatePicker.Size = New-Object System.Drawing.Size(200, 20)
				$startDatePicker.TabIndex = 6
				#
				# useScheduleCheckBox
				#
				$useScheduleCheckBox.AutoSize = $true
				$useScheduleCheckBox.Location = New-Object System.Drawing.Point(12, 284)
				$useScheduleCheckBox.Name = "useScheduleCheckBox"
				$useScheduleCheckBox.Size = New-Object System.Drawing.Size(139, 17)
				$useScheduleCheckBox.TabIndex = 5
				$useScheduleCheckBox.Text = "Use Start and End Date"
				$useScheduleCheckBox.UseVisualStyleBackColor = $true
				$useScheduleCheckBox.Add_CheckedChanged({
					if ($useScheduleCheckBox.Checked -eq $true) {
						$startDatePicker.Enabled = $true
						$endDatePicker.Enabled = $true
					}
					else {
						$startDatePicker.Enabled = $false
						$endDatePicker.Enabled = $false
					}
				})
				#
				# endDatePicker
				#
				$endDatePicker.Enabled = $false
				$endDatePicker.Location = New-Object System.Drawing.Point(172, 281)
				$endDatePicker.Name = "endDatePicker"
				$endDatePicker.Size = New-Object System.Drawing.Size(200, 20)
				$endDatePicker.TabIndex = 7
				#
				# addAutoReplyForm
				#
				$addAutoReplyForm.ClientSize = New-Object System.Drawing.Size(384, 345)
				$addAutoReplyForm.Controls.Add($endDatePicker)
				$addAutoReplyForm.Controls.Add($useScheduleCheckBox)
				$addAutoReplyForm.Controls.Add($startDatePicker)
				$addAutoReplyForm.Controls.Add($confirmAutoReplyButton)
				$addAutoReplyForm.Controls.Add($matchRepliesCheckBox)
				$addAutoReplyForm.Controls.Add($externalReplyLabel)
				$addAutoReplyForm.Controls.Add($externalReplyTextBox)
				$addAutoReplyForm.Controls.Add($internalReplyTextBox)
				$addAutoReplyForm.Controls.Add($internalReplyLabel)
				$addAutoReplyForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
				$addAutoReplyForm.MaximizeBox = $false
				$addAutoReplyForm.MinimizeBox = $false
				$addAutoReplyForm.Name = "addAutoReplyForm"
				$addAutoReplyForm.Text = "Add Auto-Reply"
				$addAutoReplyForm.Add_Shown({$addAutoReplyForm.Activate()})

				$addAutoReplyForm.ShowDialog()
				$addAutoReplyForm.Dispose()
			}
		}
		$emailInputBox.Text = ""
		$adNameInputBox.Text = ""
		Write-Host "`nFinished blocking $user." -ForegroundColor Cyan
		CheckForErrors
		OperationComplete
	}

	$ScriptForm2 = New-Object System.Windows.Forms.Form

	$emailLabel = New-Object System.Windows.Forms.Label
	$emailInputBox = New-Object System.Windows.Forms.TextBox
	$blockButton = New-Object System.Windows.Forms.Button
	$adNameLabel = New-Object System.Windows.Forms.Label
	$adNameInputBox = New-Object System.Windows.Forms.TextBox
	$emailCheckBox = New-Object System.Windows.Forms.CheckBox
	$adCheckBox = New-Object System.Windows.Forms.CheckBox
	$emailOptionsGroupBox = New-Object System.Windows.Forms.GroupBox
	$addMembersCheckBox = New-Object System.Windows.Forms.CheckBox
	$addAutoReplyCheckBox = New-Object System.Windows.Forms.CheckBox
	#
	# emailLabel
	#
	$emailLabel.AutoSize = $true
	$emailLabel.Location = New-Object System.Drawing.Point(12, 15)
	$emailLabel.Name = "emailLabel"
	$emailLabel.Size = New-Object System.Drawing.Size(35, 13)
	$emailLabel.TabIndex = 0
	$emailLabel.Text = "Email:"
	#
	# emailInputBox
	#
	$emailInputBox.Location = New-Object System.Drawing.Point(53, 12)
	$emailInputBox.Name = "emailInputBox"
	$emailInputBox.Size = New-Object System.Drawing.Size(219, 20)
	$emailInputBox.TabIndex = 1
	$emailInputBox.Add_TextChanged({
		$email = $emailInputBox.Text
		$splitEmail = $email -split "@"
		$adNameInputBox.Text = $splitEmail[0]
	})
	#
	# blockButton
	#
	$blockButton.Location = New-Object System.Drawing.Point(12, 136)
	$blockButton.Name = "blockButton"
	$blockButton.Size = New-Object System.Drawing.Size(260, 23)
	$blockButton.TabIndex = 9
	$blockButton.Text = "Block"
	$blockButton.UseVisualStyleBackColor = $true
	$blockButton.Add_Click({OnBlockButtonClick})
	#
	# adNameLabel
	#
	$adNameLabel.AutoSize = $true
	$adNameLabel.Location = New-Object System.Drawing.Point(12, 42)
	$adNameLabel.Name = "adNameLabel"
	$adNameLabel.Size = New-Object System.Drawing.Size(76, 13)
	$adNameLabel.TabIndex = 2
	$adNameLabel.Text = "AD Username:"
	#
	# adNameInputBox
	#
	$adNameInputBox.Location = New-Object System.Drawing.Point(94, 39)
	$adNameInputBox.Name = "adNameInputBox"
	$adNameInputBox.Size = New-Object System.Drawing.Size(178, 20)
	$adNameInputBox.TabIndex = 3
	#
	# emailCheckBox
	#
	$emailCheckBox.AutoSize = $true
	$emailCheckBox.Checked = $true
	$emailCheckBox.CheckState = [System.Windows.Forms.CheckState]::Checked
	$emailCheckBox.Location = New-Object System.Drawing.Point(12, 68)
	$emailCheckBox.Name = "emailCheckBox"
	$emailCheckBox.Size = New-Object System.Drawing.Size(81, 17)
	$emailCheckBox.TabIndex = 4
	$emailCheckBox.Text = "Block Email"
	$emailCheckBox.UseVisualStyleBackColor = $true
	$emailCheckBox.Add_CheckedChanged({
		if ($emailCheckBox.Checked -eq $true) {
			$emailInputBox.Enabled = $true
			$emailOptionsGroupBox.Enabled = $true
			$addMembersCheckBox.Enabled = $true
			$addAutoReplyCheckBox.Enabled = $true
		} elseif ($emailCheckBox.Checked -eq $false) {
			$emailInputBox.Enabled = $false
			$emailOptionsGroupBox.Enabled = $false
			$addMembersCheckBox.Enabled = $false
			$addAutoReplyCheckBox.Enabled = $false
		}
	})
	#
	# adCheckBox
	#
	$adCheckBox.AutoSize = $true
	$adCheckBox.Checked = $true
	$adCheckBox.CheckState = [System.Windows.Forms.CheckState]::Checked
	$adCheckBox.Location = New-Object System.Drawing.Point(12, 92)
	$adCheckBox.Name = "adCheckBox"
	$adCheckBox.Size = New-Object System.Drawing.Size(71, 17)
	$adCheckBox.TabIndex = 5
	$adCheckBox.Text = "Block AD"
	$adCheckBox.UseVisualStyleBackColor = $true
	$adCheckBox.Add_CheckedChanged({
		if ($adCheckBox.Checked -eq $true) {
			$adNameInputBox.Enabled = $true
		} elseif ($adCheckBox.Checked -eq $false) {
			$adNameInputBox.Enabled = $false
		}
	})
	#
	# emailOptionsGroupBox
	#
	$emailOptionsGroupBox.Controls.Add($addAutoReplyCheckBox)
	$emailOptionsGroupBox.Controls.Add($addMembersCheckBox)
	$emailOptionsGroupBox.Location = New-Object System.Drawing.Point(94, 65)
	$emailOptionsGroupBox.Name = "emailOptionsGroupBox"
	$emailOptionsGroupBox.Size = New-Object System.Drawing.Size(178, 65)
	$emailOptionsGroupBox.TabIndex = 6
	$emailOptionsGroupBox.TabStop = $false
	$emailOptionsGroupBox.Text = "EmailOptions"
	#
	# addMembersCheckBox
	#
	$addMembersCheckBox.AutoSize = $true
	$addMembersCheckBox.Checked = $true
	$addMembersCheckBox.CheckState = [System.Windows.Forms.CheckState]::Checked
	$addMembersCheckBox.Location = New-Object System.Drawing.Point(6, 19)
	$addMembersCheckBox.Name = "addMembersCheckBox"
	$addMembersCheckBox.Size = New-Object System.Drawing.Size(91, 17)
	$addMembersCheckBox.TabIndex = 7
	$addMembersCheckBox.Text = "Add Members"
	$addMembersCheckBox.UseVisualStyleBackColor = $true
	#
	# addAutoReplyCheckBox
	#
	$addAutoReplyCheckBox.AutoSize = $true
	$addAutoReplyCheckBox.Location = New-Object System.Drawing.Point(6, 42)
	$addAutoReplyCheckBox.Name = "addAutoReplyCheckBox"
	$addAutoReplyCheckBox.Size = New-Object System.Drawing.Size(100, 17)
	$addAutoReplyCheckBox.TabIndex = 8
	$addAutoReplyCheckBox.Text = "Add Auto-Reply"
	$addAutoReplyCheckBox.UseVisualStyleBackColor = $true
	#
	# ScriptForm2
	#
	$ScriptForm2.ClientSize = New-Object System.Drawing.Size(284, 171)
	$ScriptForm2.Controls.Add($emailOptionsGroupBox)
	$ScriptForm2.Controls.Add($adCheckBox)
	$ScriptForm2.Controls.Add($emailCheckBox)
	$ScriptForm2.Controls.Add($adNameInputBox)
	$ScriptForm2.Controls.Add($adNameLabel)
	$ScriptForm2.Controls.Add($blockButton)
	$ScriptForm2.Controls.Add($emailInputBox)
	$ScriptForm2.Controls.Add($emailLabel)
	$ScriptForm2.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$ScriptForm2.MaximizeBox = $false
	$ScriptForm2.MinimizeBox = $false
	$ScriptForm2.Name = "ScriptForm2"
	$ScriptForm2.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$ScriptForm2.Text = "Block-User"
	$ScriptForm2.Add_Shown({$ScriptForm2.Activate()})

	$progressBar1.Value = 0
	Write-Host "Loaded ScriptForm2."
	CheckForErrors

	$ScriptForm2.ShowDialog()
	$ScriptForm2.Dispose()

	Stop-Transcript
}
function Clear-RecycleBin {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Clear-RecycleBin.txt"
	Write-Host "Running Clear-RecycleBin script..."
	$progressBar1.Value = 10

	$scriptForm11 = New-Object System.Windows.Forms.Form

	$components = New-Object System.ComponentModel.Container
	$clearBinsButton = New-Object System.Windows.Forms.Button
	$label1 = New-Object System.Windows.Forms.Label
	$confirmationCheckBox = New-Object System.Windows.Forms.CheckBox
	$toolTip1 = New-Object System.Windows.Forms.ToolTip($components)
	#
	# clearBinsButton
	#
	$clearBinsButton.Enabled = $false
	$clearBinsButton.Location = New-Object System.Drawing.Point(12, 76)
	$clearBinsButton.Name = "clearBinsButton"
	$clearBinsButton.Size = New-Object System.Drawing.Size(210, 23)
	$clearBinsButton.TabIndex = 3
	$clearBinsButton.Text = "Clear Recycle Bins"
	$clearBinsButton.UseVisualStyleBackColor = $true
	$clearBinsButton.Add_Click({
		$progressBar1.Value = 30
		Remove-Item -Path "C:\`$Recycle.Bin\*" -Recurse -Force
		$progressBar1.Value = 90
		CheckForErrors
		OperationComplete
	})
	#
	# label1
	#
	$label1.AutoSize = $true
	$label1.Location = New-Object System.Drawing.Point(9, 9)
	$label1.Name = "label1"
	$label1.Size = New-Object System.Drawing.Size(211, 26)
	$label1.TabIndex = 0
	$label1.Text = "Clears all contents of all recycle bins on`r`nthis computer."
	$toolTip1.SetToolTip($label1, "On a terminal server this will empty everyone's recycle bins.")
	#
	# confirmationCheckBox
	#
	$confirmationCheckBox.AutoSize = $true
	$confirmationCheckBox.Location = New-Object System.Drawing.Point(12, 53)
	$confirmationCheckBox.Name = "confirmationCheckBox"
	$confirmationCheckBox.Size = New-Object System.Drawing.Size(159, 17)
	$confirmationCheckBox.TabIndex = 2
	$confirmationCheckBox.Text = "I understand what this does."
	$confirmationCheckBox.UseVisualStyleBackColor = $true
	$confirmationCheckBox.Add_CheckedChanged({
		if ($confirmationCheckBox.Checked) {
			Write-Host "Confirmation box checked."
			$clearBinsButton.Enabled = $true
		} else {
			Write-Host "Confirmation box unchecked."
			$clearBinsButton.Enabled = $false
		}
	})
	#
	# toolTip1
	#
	$toolTip1.ToolTipTitle = "Example:"
	#
	# scriptForm11
	#
	$scriptForm11.ClientSize = New-Object System.Drawing.Size(234, 111)
	$scriptForm11.Controls.Add($confirmationCheckBox)
	$scriptForm11.Controls.Add($label1)
	$scriptForm11.Controls.Add($clearBinsButton)
	$scriptForm11.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$scriptForm11.MaximizeBox = $false
	$scriptForm11.MinimizeBox = $false
	$scriptForm11.Name = "scriptForm11"
	$scriptForm11.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$scriptForm11.Text = "Clear-RecycleBin"
	$scriptForm11.Add_Shown({$scriptForm11.Activate()})

	Write-Host "Loaded ScriptForm11."
	$progressBar1.Value = 0

	$scriptForm11.ShowDialog()
	$scriptForm11.Dispose()

	Stop-Transcript
}
function Convert-UnifiedGroupToDistributionGroup {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Convert-UnifiedGroupToDistributionGroup.txt"
	Write-Host "Running Convert-UnifiedGroupToDistributionList script..."
	$progressBar1.Value = 10
	function OnCreateButtonClick {
		Write-Host "Create button clicked."
		$progressBar1.Value = 5
		$M365GroupName = $sourceInputBox.Text
		$OldGroupName = $sourceInputBox.Text -Split "@"
		$DistGroupName = $OldGroupName[0] + "-New"
		New-DistributionGroup -Name $DistGroupName
		Write-Host "Created $DistGroupName"
		$progressBar1.Value = 10
		$M365GroupMembers = Get-UnifiedGroup -Identity $M365GroupName | Get-UnifiedGroupLinks -LinkType Member | Select-Object -expandproperty PrimarySmtpAddress
		Foreach ($member in $M365GroupMembers) {
		Write-Host "Adding $member..."
		$progressBar1.Value = 20
		Add-DistributionGroupMember -Identity $DistGroupName -Member $member
		$progressBar1.Value = 80
		}
		CheckForErrors
		OperationComplete
	}
	
	function OnTemplateButtonClick {
		Write-Host "Open template button clicked."
		$progressBar1.Value = 10
		Invoke-Item ".\Templates\Convert-UnifiedGroupToDistributionList.txt"
		$progressBar1.Value = 0
		CheckForErrors
	}
	
	function OnCreateBulkButtonClick {
		Write-Host "Create bulk button clicked."
		$progressBar1.Value = 2
		Get-Content ".\Templates\Convert-UnifiedGroupToDistributionList.txt" | ForEach-Object {
			$progressBar1.Value = 5
			$OldGroupName = $_ -Split "@"
			$DistGroupName = $OldGroupName[0] + "-New"
			New-DistributionGroup -Name $DistGroupName
			Write-Host "Created $DistGroupName"
			$progressBar1.Value = 10
			$M365GroupMembers = Get-UnifiedGroup -Identity $_ | Get-UnifiedGroupLinks -LinkType Member | Select-Object -expandproperty PrimarySmtpAddress
			Foreach ($member in $M365GroupMembers) {
				Write-Host "Adding $member..."
				$progressBar1.Value = 20
				Add-DistributionGroupMember -Identity $DistGroupName -Member $member
				$progressBar1.Value = 80
			}
		}
		Write-Host "Done cycling through text file."
		CheckForErrors
		OperationComplete
	}
	
	$ScriptForm6 = New-Object System.Windows.Forms.Form
	
	$sourceLabel = New-Object System.Windows.Forms.Label
	$sourceInputBox = New-Object System.Windows.Forms.TextBox
	$tabControl1 = New-Object System.Windows.Forms.TabControl
	$tabPage1 = New-Object System.Windows.Forms.TabPage
	$tabPage2 = New-Object System.Windows.Forms.TabPage
	$createButton = New-Object System.Windows.Forms.Button
	$templateOpenButton = New-Object System.Windows.Forms.Button
	$createBulkButton = New-Object System.Windows.Forms.Button
	#
	# sourceLabel
	#
	$sourceLabel.AutoSize = $true
	$sourceLabel.Location = New-Object System.Drawing.Point(6, 9)
	$sourceLabel.Name = "sourceLabel"
	$sourceLabel.Size = New-Object System.Drawing.Size(84, 13)
	$sourceLabel.TabIndex = 0
	$sourceLabel.Text = "Source address:"
	#
	# sourceInputBox
	#
	$sourceInputBox.Location = New-Object System.Drawing.Point(96, 6)
	$sourceInputBox.Name = "sourceInputBox"
	$sourceInputBox.Size = New-Object System.Drawing.Size(189, 20)
	$sourceInputBox.TabIndex = 2
	#
	# tabControl1
	#
	$tabControl1.Controls.Add($tabPage1)
	$tabControl1.Controls.Add($tabPage2)
	$tabControl1.Location = New-Object System.Drawing.Point(12, 12)
	$tabControl1.Name = "tabControl1"
	$tabControl1.SelectedIndex = 0
	$tabControl1.Size = New-Object System.Drawing.Size(299, 90)
	$tabControl1.TabIndex = 4
	#
	# tabPage1
	#
	$tabPage1.Controls.Add($createButton)
	$tabPage1.Controls.Add($sourceLabel)
	$tabPage1.Controls.Add($newNameLabel)
	$tabPage1.Controls.Add($destinationInputBox)
	$tabPage1.Controls.Add($sourceInputBox)
	$tabPage1.Location = New-Object System.Drawing.Point(4, 22)
	$tabPage1.Name = "tabPage1"
	$tabPage1.Padding = New-Object System.Windows.Forms.Padding(3)
	$tabPage1.Size = New-Object System.Drawing.Size(291, 92)
	$tabPage1.TabIndex = 0
	$tabPage1.Text = "Single"
	$tabPage1.UseVisualStyleBackColor = $true
	#
	# tabPage2
	#
	$tabPage2.Controls.Add($createBulkButton)
	$tabPage2.Controls.Add($templateOpenButton)
	$tabPage2.Location = New-Object System.Drawing.Point(4, 22)
	$tabPage2.Name = "tabPage2"
	$tabPage2.Padding = New-Object System.Windows.Forms.Padding(3)
	$tabPage2.Size = New-Object System.Drawing.Size(291, 92)
	$tabPage2.TabIndex = 1
	$tabPage2.Text = "Bulk"
	$tabPage2.UseVisualStyleBackColor = $true
	#
	# createButton
	#
	$createButton.Location = New-Object System.Drawing.Point(6, 35)
	$createButton.Name = "createButton"
	$createButton.Size = New-Object System.Drawing.Size(279, 23)
	$createButton.TabIndex = 4
	$createButton.Text = "Create"
	$createButton.UseVisualStyleBackColor = $true
	$createButton.Add_Click({ OnCreateButtonClick })
	#
	# templateOpenButton
	#
	$templateOpenButton.Location = New-Object System.Drawing.Point(6, 6)
	$templateOpenButton.Name = "templateOpenButton"
	$templateOpenButton.Size = New-Object System.Drawing.Size(279, 23)
	$templateOpenButton.TabIndex = 0
	$templateOpenButton.Text = "Open Bulk txt File"
	$templateOpenButton.UseVisualStyleBackColor = $true
	$templateOpenButton.Add_Click({ OnTemplateButtonClick })
	#
	# createBulkButton
	#
	$createBulkButton.Location = New-Object System.Drawing.Point(6, 35)
	$createBulkButton.Name = "createBulkButton"
	$createBulkButton.Size = New-Object System.Drawing.Size(279, 23)
	$createBulkButton.TabIndex = 1
	$createBulkButton.Text = "Create"
	$createBulkButton.UseVisualStyleBackColor = $true
	$createBulkButton.Add_Click({ OnCreateBulkButtonClick })
	#
	# ScriptForm6
	#
	$ScriptForm6.ClientSize = New-Object System.Drawing.Size(321, 110)
	$ScriptForm6.Controls.Add($tabControl1)
	$ScriptForm6.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$ScriptForm6.MaximizeBox = $false
	$ScriptForm6.MinimizeBox = $false
	$ScriptForm6.Name = "ScriptForm6"
	$ScriptForm6.Text = "Convert-UnifiedGroupToDistributionList"
	$ScriptForm6.StartPosition = "CenterParent"
	$ScriptForm6.Add_Shown({$ScriptForm6.Activate()})
	
	Write-Host "Loaded ScriptForm6."
	$progressBar1.Value = 0

	$ScriptForm6.ShowDialog()
	$ScriptForm6.Dispose()

	Stop-Transcript
}
function Enable-Archive {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Enable-Archive.txt"
	Write-Host "Running Enable-Archive script..."
	$progressBar1.Value = 10
	function OnArchiveButtonClick {
		$mailbox = $archiveInputBox.Text
		$progressBar1.Value = 20
		Enable-Mailbox -Identity $mailbox -Archive
		$progressBar1.Value = 80
		CheckForErrors
		OperationComplete
	}
	
	function OnJumpstartButtonClick {
		$mailbox = $archiveInputBox.Text
		$progressBar1.Value = 20
		Start-ManagedFolderAssistant -Identity $mailbox
		$progressBar1.Value = 80
		CheckForErrors
		OperationComplete
	}
	
	function OnExpandButtonClick {
		$getUserConfirmation = ShowWarningForm "Turning on AutoExpandingArchive is irreversible - are you sure you'd like to continue?"
		if ($getUserConfirmation -eq $true) {
			Write-Host "User confirmed operation."
			$mailbox = $archiveInputBox.Text
			$progressBar1.Value = 20
			Enable-Mailbox -Identity $mailbox -AutoExpandingArchive
			Write-Host "Enabled auto expanding archive for $mailbox."
			$progressBar1.Value = 80
			CheckForErrors
			OperationComplete
		} elseif ($getUserConfirmation -eq $false) {
			Write-Host "User cancelled operation."
		} else {
			Write-Host "Error, can't determine if user confirmed or cancelled."
		}
	}
	
	$ScriptForm3 = New-Object System.Windows.Forms.Form
	
	$archiveLabel = New-Object System.Windows.Forms.Label
	$archiveInputBox = New-Object System.Windows.Forms.TextBox
	$archiveButton = New-Object System.Windows.Forms.Button
	$jumpstartButton = New-Object System.Windows.Forms.Button
	$expandButton = New-Object System.Windows.Forms.Button
	#
	# archiveLabel
	#
	$archiveLabel.AutoSize = $true
	$archiveLabel.Location = New-Object System.Drawing.Point(12, 13)
	$archiveLabel.Name = "archiveLabel"
	$archiveLabel.Size = New-Object System.Drawing.Size(46, 13)
	$archiveLabel.TabIndex = 0
	$archiveLabel.Text = "Mailbox:"
	#
	# archiveInputBox
	#
	$archiveInputBox.Location = New-Object System.Drawing.Point(64, 10)
	$archiveInputBox.Name = "archiveInputBox"
	$archiveInputBox.Size = New-Object System.Drawing.Size(232, 20)
	$archiveInputBox.TabIndex = 0
	#
	# archiveButton
	#
	$archiveButton.Location = New-Object System.Drawing.Point(12, 36)
	$archiveButton.Name = "archiveButton"
	$archiveButton.Size = New-Object System.Drawing.Size(284, 23)
	$archiveButton.TabIndex = 1
	$archiveButton.Text = "Enable Archive"
	$archiveButton.UseVisualStyleBackColor = $true
	$archiveButton.Add_Click({OnArchiveButtonClick})
	#
	# jumpstartButton
	#
	$jumpstartButton.Location = New-Object System.Drawing.Point(12, 67)
	$jumpstartButton.Name = "jumpstartButton"
	$jumpstartButton.Size = New-Object System.Drawing.Size(140, 23)
	$jumpstartButton.TabIndex = 2
	$jumpstartButton.Text = "Jumpstart Archive"
	$jumpstartButton.UseVisualStyleBackColor = $true
	$jumpstartButton.Add_Click({OnJumpstartButtonClick})
	#
	# expandButton
	#
	$expandButton.Enabled = $true
	$expandButton.Location = New-Object System.Drawing.Point(156, 67)
	$expandButton.Name = "expandButton"
	$expandButton.Size = New-Object System.Drawing.Size(140, 23)
	$expandButton.TabIndex = 3
	$expandButton.Text = "Auto Expand Archive"
	$expandButton.UseVisualStyleBackColor = $true
	$expandButton.Visible = $true
	$expandButton.Add_Click({OnExpandButtonClick})
	#
	# ScriptForm3
	#
	$ScriptForm3.AcceptButton = $archiveButton
	$ScriptForm3.ClientSize = New-Object System.Drawing.Size(308, 102)
	$ScriptForm3.Controls.Add($expandButton)
	$ScriptForm3.Controls.Add($jumpstartButton)
	$ScriptForm3.Controls.Add($archiveButton)
	$ScriptForm3.Controls.Add($archiveInputBox)
	$ScriptForm3.Controls.Add($archiveLabel)
	$ScriptForm3.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$ScriptForm3.MaximizeBox = $false
	$ScriptForm3.MinimizeBox = $false
	$ScriptForm3.Name = "ScriptForm3"
	$ScriptForm3.Text = "Enable-Archive"
	$ScriptForm3.StartPosition = "CenterParent"
	$ScriptForm3.Add_Shown({$ScriptForm3.Activate()})
	
	Write-Host "Loaded ScriptForm3."
	$progressBar1.Value = 0
	
	$ScriptForm3.ShowDialog()
	$ScriptForm3.Dispose()

	Stop-Transcript
}
function Install-RequiredModules {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Install-RequiredModules.txt"
	Write-Host "Running Install-RequiredModules script..."
	$progressBar1.Value = 10
	Install-Module -Name Microsoft.Graph -Force -AllowClobber
	$progressBar1.Value = 50
	Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber
	$progressBar1.Value = 80
	CheckForErrors
	OperationComplete
	Stop-Transcript
}
function New-ADAccounts {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\New-ADAccounts.txt"
	Write-Host "Running New-ADAccounts script..."
	$progressBar1.Value = 10
	Write-Host "Importing ActiveDirectory Module..."
	Import-Module ActiveDirectory
	CheckForErrors
	$progressBar1.Value = 30
	Write-Host "Getting domain info..."
	$domain = Get-ADDomain
	CheckForErrors
	$progressBar1.Value = 40

	function OnOpenTemplateButtonClick {
		Write-Host "Open template button clicked."
		$progressBar1.Value = 10
		Invoke-Item ".\Templates\New-ADAccounts.csv"
		$progressBar1.Value = 100
		CheckForErrors
		$progressBar1.Value = 0
	}
	function OnCreateAccountsButtonClick {
		Write-Host "Checking if any SamAccountNames are over 20 characters."
		Import-Csv -Path ".\Templates\New-ADAccounts.csv" | ForEach-Object {
			if ($_.SamAccountName.Length -gt 20) {
				Write-Host "$($_.SamAccountName) is over 20 characters, requesting user confirmation." -ForegroundColor Red
				$getUserConfirmation = ShowWarningForm -warningText "One or more SamAccountNames are over 20 characters - this may cause issues.`nPlease confirm if you'd like to proceed anyways."
				if ($getUserConfirmation -eq $true) {
					Write-Host "User confirmed to continue, running script..."
					CreateADAccounts
				} else {
					Write-Host "User closed confirmation window, cancelling action..."
				}
				break
			}
		}
		Write-Host "All SamAccountNames are within 20 characters."
		CreateADAccounts
	}
	function CreateADAccounts {
		Write-Host "Importing template csv..."
		$progressBar1.Value = 10
		$csvFile = Import-Csv -Path ".\Templates\New-ADAccounts.csv"
		$progressBar1.Value = 20
		CheckForErrors

		foreach ($row in $csvFile) {
			Write-Host "Gathering info..."

			$sourceUser = Get-ADUser -Identity $row.SourceUser -Properties *

			if ($null -eq $sourceUser) {
				Write-Host "Source user '$($row.SourceUser)' not found. Skipping user creation for '$($row.SamAccountName)'."
				continue
			}

			$ouPath = $sourceUser.DistinguishedName -replace "CN=[^,]+,", ""
			$ou = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouPath'"

			if ($null -eq $ou) {
				Write-Host "OU '$ouPath' not found. Skipping user creation for '$($row.SamAccountName)'."
				continue
			}
			
			$forest = $adDomainInput.Text
			$displayName = $row.GivenName + " " + $row.Surname
			$userPrincipalName = $row.SamAccountName + "@$forest"
			$samAccountName = $row.SamAccountName
			$progressBar1.Value = 30
			
			Write-Host "Creating new user $samAccountName..."
			New-ADUser -SamAccountName $samAccountName -Name $displayName -UserPrincipalName $userPrincipalName -DisplayName $displayName -AccountPassword (ConvertTo-SecureString $row.Password -AsPlainText -Force) -Enabled $true -Path $ou.DistinguishedName -GivenName $row.GivenName -Surname $row.Surname  
			$progressBar1.Value = 40

			$newUser = Get-ADUser -Filter "SamAccountName -eq '$($row.SamAccountName)'"
			
			Write-Host "Copying attributes from source user $($sourceUser.SamAccountName) to new user $($newUser.SamAccountName)..."
			# Copy additional attributes from the source user
			Set-ADUser $newUser -ProfilePath $sourceUser.ProfilePath
			Set-ADUser $newUser -ScriptPath $sourceUser.ScriptPath
			Set-ADUser $newUser -PasswordNeverExpires $sourceUser.PasswordNeverExpires
			Set-ADUser $newUser -CannotChangePassword $sourceUser.CannotChangePassword
			$progressBar1.Value = 50
			
			Write-Host "Checking if source user $($sourceUser.SamAccountName) has a Home Directory..."
			# Check if the source user has a HomeDirectory
			if ($sourceUser.HomeDirectory) {
				Write-Host "Source user $($sourceUser.SamAccountName) has a Home Directory, copying to new user $($newUser.SamAccountName)..."
				# Construct HomeDirectory path
				$originalPath = $sourceUser.HomeDirectory
				$parentPath = Split-Path $originalPath -Parent
				$homeDirectory = Join-Path $parentPath $row.SamAccountName

				# Create HomeDirectory and HomeDrive
				New-Item -Path $homeDirectory -ItemType Directory
				$aclPath = $homeDirectory
				$acl = Get-Acl $aclPath

				$identity = "$forest\$samAccountName"
				$rights = "Modify"
				$inheritanceFlags = "ContainerInherit, ObjectInherit"
				$propagationFlags = "None"
				$accessControlType = "Allow"
				$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$identity","$rights","$inheritanceFlags","$propagationFlags","$accessControlType")
				$acl.AddAccessRule($rule)
				Set-Acl $aclPath $acl
				$progressBar1.Value = 60

				# Add HomeDirectory and HomeDrive
				Set-ADUser $newUser -HomeDrive $sourceUser.HomeDrive
				Set-ADUser $newUser -HomeDirectory $homeDirectory
			} else {
				Write-Host "Source user $($sourceUser.SamAccountName) does not have a HomeDirectory. Skipping HomeDirectory creation for the new user $($newUser.SamAccountName)."
			}
			$progressBar1.Value = 70
			
			Write-Host "Copying group membership from source user $($sourceUser.SamAccountName) to new user $($newUser.SamAccountName)..."
			# Copy security group memberships
			$sourceGroups = Get-ADPrincipalGroupMembership -Identity $sourceUser
			foreach ($group in $sourceGroups) {
				# Check if the new user is already a member of the group
				$isMember = Get-ADGroupMember -Identity $group -Recursive | Where-Object { $_.SamAccountName -eq $newUser.SamAccountName }
				if ($null -eq $isMember) {
					# Add the new user to the group if they are not already a member
					Add-ADGroupMember -Identity $group -Members $newUser
				}
			}
			Write-Host "Finished creating new user $($newuser.SamAccountName)."
		}
		CheckForErrors
		OperationComplete
	}

	$scriptForm9 = New-Object System.Windows.Forms.Form

	$adDomainInput = New-Object System.Windows.Forms.TextBox
	$adDomainLabel = New-Object System.Windows.Forms.Label
	$emailDomainLabel = New-Object System.Windows.Forms.Label
	$emailDomainInput = New-Object System.Windows.Forms.TextBox
	$openTemplateButton = New-Object System.Windows.Forms.Button
	$createAccountsButton = New-Object System.Windows.Forms.Button
	#
	# adDomainInput
	#
	$adDomainInput.Location = New-Object System.Drawing.Point(82, 10)
	$adDomainInput.Name = "adDomainInput"
	$adDomainInput.Size = New-Object System.Drawing.Size(190, 20)
	$adDomainInput.TabIndex = 0
	$adDomainInput.Text = $domain.forest
	#
	# adDomainLabel
	#
	$adDomainLabel.AutoSize = $true
	$adDomainLabel.Location = New-Object System.Drawing.Point(12, 13)
	$adDomainLabel.Name = "adDomainLabel"
	$adDomainLabel.Size = New-Object System.Drawing.Size(64, 13)
	$adDomainLabel.TabIndex = 1
	$adDomainLabel.Text = "AD Domain:"
	#
	# emailDomainLabel
	#
	$emailDomainLabel.AutoSize = $true
	$emailDomainLabel.Location = New-Object System.Drawing.Point(12, 43)
	$emailDomainLabel.Name = "emailDomainLabel"
	$emailDomainLabel.Size = New-Object System.Drawing.Size(74, 13)
	$emailDomainLabel.TabIndex = 2
	$emailDomainLabel.Text = "Email Domain:"
	$emailDomainLabel.Visible = $false
	$emailDomainLabel.Enabled = $false
	#
	# emailDomainInput
	#
	$emailDomainInput.Location = New-Object System.Drawing.Point(92, 40)
	$emailDomainInput.Name = "emailDomainInput"
	$emailDomainInput.Size = New-Object System.Drawing.Size(180, 20)
	$emailDomainInput.TabIndex = 3
	$emailDomainInput.Visible = $false
	$emailDomainInput.Enabled = $false
	#
	# openTemplateButton
	#
	$openTemplateButton.Location = New-Object System.Drawing.Point(12, 67)
	$openTemplateButton.Name = "openTemplateButton"
	$openTemplateButton.Size = New-Object System.Drawing.Size(260, 23)
	$openTemplateButton.TabIndex = 4
	$openTemplateButton.Text = "Open Template"
	$openTemplateButton.UseVisualStyleBackColor = $true
	$openTemplateButton.Add_Click({OnOpenTemplateButtonClick})
	#
	# createAccountsButton
	#
	$createAccountsButton.Location = New-Object System.Drawing.Point(12, 96)
	$createAccountsButton.Name = "createAccountsButton"
	$createAccountsButton.Size = New-Object System.Drawing.Size(259, 23)
	$createAccountsButton.TabIndex = 5
	$createAccountsButton.Text = "Create Accounts"
	$createAccountsButton.UseVisualStyleBackColor = $true
	$createAccountsButton.Add_Click({OnCreateAccountsButtonClick})
	#
	# scriptForm9
	#
	$scriptForm9.ClientSize = New-Object System.Drawing.Size(284, 131)
	$scriptForm9.Controls.Add($createAccountsButton)
	$scriptForm9.Controls.Add($openTemplateButton)
	$scriptForm9.Controls.Add($emailDomainInput)
	$scriptForm9.Controls.Add($emailDomainLabel)
	$scriptForm9.Controls.Add($adDomainLabel)
	$scriptForm9.Controls.Add($adDomainInput)
	$scriptForm9.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$scriptForm9.MaximizeBox = $false
	$scriptForm9.MinimizeBox = $false
	$scriptForm9.Name = "scriptForm9"
	$scriptForm9.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$scriptForm9.Text = "New-ADAccounts"
	$scriptForm9.Add_Shown({$scriptForm9.Activate()})

	Write-Host "Loaded ScriptForm9."
	$progressBar1.Value = 0

	$scriptForm9.ShowDialog()
	$scriptForm9.Dispose()

	Stop-Transcript
}
function New-ADAndEmailAccounts {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\New-ADAndEmailAccounts.txt"
	Write-Host "Running New-ADAndEmailAccounts script..."
	$progressBar1.Value = 10
	Write-Host "Importing ActiveDirectory Module..."
	Import-Module ActiveDirectory
	CheckForErrors
	$progressBar1.Value = 30
	Write-Host "Getting domain info..."
	$domain = Get-ADDomain
	CheckForErrors
	$progressBar1.Value = 40

	function OnOpenTemplateButtonClick {
		Write-Host "Open template button clicked."
		$progressBar1.Value = 10
		Invoke-Item ".\Templates\New-ADAndEmailAccounts.csv"
		$progressBar1.Value = 100
		CheckForErrors
		$progressBar1.Value = 0
	}
	function OnCreateAccountsButtonClick {
		Write-Host "Checking if any SamAccountNames are over 20 characters."
		Import-Csv -Path ".\Templates\New-ADAndEmailAccounts.csv" | ForEach-Object {
			if ($_.SamAccountName.Length -gt 20) {
				Write-Host "$($_.SamAccountName) is over 20 characters, requesting user confirmation." -ForegroundColor Red
				$getUserConfirmation = ShowWarningForm -warningText "One or more SamAccountNames are over 20 characters - this may cause issues.`nPlease confirm if you'd like to proceed anyways."
				if ($getUserConfirmation -eq $true) {
					Write-Host "User confirmed to continue, running script..."
					CreateAccounts
				} else {
					Write-Host "User closed confirmation window, cancelling action..."
				}
				break
			}
		}
		Write-Host "All SamAccountNames are within 20 characters."
		CreateAccounts
	}
	function CreateAccounts {
		Write-Host "Importing template csv..."
		$progressBar1.Value = 10
		$csvFile = Import-Csv -Path ".\Templates\New-ADAndEmailAccounts.csv"
		$progressBar1.Value = 30
		CheckForErrors
		foreach ($row in $csvFile) {
			Write-Host "Gathering info..."

			$sourceUser = Get-ADUser -Identity $row.SourceUser -Properties *
		
			if ($null -eq $sourceUser) {
				Write-Host "Source user '$($row.SourceUser)' not found. Skipping user creation for '$($row.SamAccountName)'."
				continue
			}
		
			$ouPath = $sourceUser.DistinguishedName -replace "CN=[^,]+,", ""
			$ou = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouPath'"
		
			if ($null -eq $ou) {
				Write-Host "OU '$ouPath' not found. Skipping user creation for '$($row.SamAccountName)'."
				continue
			}

			$forest = $adDomainInput.Text
			$domain = $emailDomainInput.Text -split '\.'
			$emailDomain = $domain[0]
			$topLevelDomain = $domain[1]
			$displayName = $row.GivenName + " " + $row.Surname
			$samAccountName = $row.SamAccountName
			$userPrincipalName = $row.SamAccountName + "@$forest"
			$emailAddress = $row.SamAccountName + "@$emailDomain.$topLevelDomain"
			# $aliasAddress = $row.SamAccountName + "@$emailDomain.onmicrosoft.com"
			$progressBar1.Value = 30
			
			Write-Host "Creating new user $samAccountName..."
			New-ADUser -SamAccountName $row.SamAccountName -Name $displayName -UserPrincipalName $userPrincipalName -DisplayName $displayName -AccountPassword (ConvertTo-SecureString $row.Password -AsPlainText -Force) -Enabled $true -Path $ou.DistinguishedName -GivenName $row.GivenName -Surname $row.Surname
			$progressBar1.Value = 40
		
			$newUser = Get-ADUser -Filter "SamAccountName -eq '$($row.SamAccountName)'"
			
			Write-Host "Copying attributes from source user $($sourceUser.SamAccountName) to new user $($newUser.SamAccountName)..."
			# Copy additional attributes from the source user
			Set-ADUser $newUser -ProfilePath $sourceUser.ProfilePath
			Set-ADUser $newUser -ScriptPath $sourceUser.ScriptPath
			Set-ADUser $newUser -PasswordNeverExpires $sourceUser.PasswordNeverExpires
			Set-ADUser $newUser -CannotChangePassword $sourceUser.CannotChangePassword
			$progressBar1.Value = 50
			
			Write-Host "Checking if source user $($sourceUser.SamAccountName) has a Home Directory..."
			# Check if the source user has a HomeDirectory
			if ($sourceUser.HomeDirectory) {
				Write-Host "Source user $($sourceUser.SamAccountName) has a Home Directory, copying to new user $($newUser.SamAccountName)..."
				# Construct HomeDirectory path
				$originalPath = $sourceUser.HomeDirectory
				$parentPath = Split-Path $originalPath -Parent
				$homeDirectory = Join-Path $parentPath $row.SamAccountName

				# Create HomeDirectory and HomeDrive
				New-Item -Path $homeDirectory -ItemType Directory
				$aclPath = $homeDirectory
				$acl = Get-Acl $aclPath

				$identity = "$forest\$samAccountName"
				$rights = "Modify"
				$inheritanceFlags = "ContainerInherit, ObjectInherit"
				$propagationFlags = "None"
				$accessControlType = "Allow"
				$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$identity","$rights","$inheritanceFlags","$propagationFlags","$accessControlType")
				$acl.AddAccessRule($rule)
				Set-Acl $aclPath $acl
				$progressBar1.Value = 60

				# Add HomeDirectory and HomeDrive
				Set-ADUser $newUser -HomeDrive $sourceUser.HomeDrive
				Set-ADUser $newUser -HomeDirectory $homeDirectory
			} else {
				Write-Host "Source user $($sourceUser.SamAccountName) does not have a HomeDirectory. Skipping HomeDirectory creation for the new user $($newUser.SamAccountName)."
			}
			$progressBar1.Value = 70
			
			Write-Host "Copying group membership from source user $($sourceUser.SamAccountName) to new user $($newUser.SamAccountName)..."
			# Copy security group memberships
			$sourceGroups = Get-ADPrincipalGroupMembership -Identity $sourceUser
			foreach ($group in $sourceGroups) {
				# Check if the new user is already a member of the group
				$isMember = Get-ADGroupMember -Identity $group -Recursive | Where-Object { $_.SamAccountName -eq $newUser.SamAccountName }
				if ($null -eq $isMember) {
					# Add the new user to the group if they are not already a member
					Add-ADGroupMember -Identity $group -Members $newUser
				}
			}
			$progressBar1.Value = 80
		
			# Create mailbox
			$passwordProfile = @{
				ForceChangePasswordNextSignIn = $false
				Password = $row.Password
			}
		
			New-MgUser -AccountEnabled -PasswordProfile $passwordProfile -DisplayName $displayName -GivenName $row.GivenName -Surname $row.Surname -UserPrincipalName $emailAddress -MailNickname $row.SamAccountName -UsageLocation US
			$progressBar1.Value = 90

			# Set license
			switch ($licenseComboBox.Text) {
				"Exchange Online (Plan 1)" {
					Write-Host "Assigning Exchange Online (Plan 1) license..."
					Set-MgUserLicense -UserId $emailAddress -AddLicenses @{SkuId = "4b9405b0-7788-4568-add1-99614e613b69"} -RemoveLicenses @()
				}
				"Exchange Online (Plan 2)" {
					Write-Host "Assigning Exchange Online (Plan 2) license..."
					Set-MgUserLicense -UserId $emailAddress -AddLicenses @{SkuId = "19ec0d23-8335-4cbd-94ac-6050e30712fa"} -RemoveLicenses @()
				}
				"Microsoft 365 Business Basic" {
					Write-Host "Assigning Microsoft 365 Business Basic license..."
					Set-MgUserLicense -UserId $emailAddress -AddLicenses @{SkuId = "3b555118-da6a-4418-894f-7df1e2096870"} -RemoveLicenses @()
				}
				"Microsoft 365 Business Standard" {
					Write-Host "Assigning Microsoft 365 Business Standard license..."
					Set-MgUserLicense -UserId $emailAddress -AddLicenses @{SkuId = "f245ecc8-75af-4f8e-b61f-27d8114de5f3"} -RemoveLicenses @()
				}
				"Microsoft 365 Business Premium" {
					Write-Host "Assigning Microsoft 365 Business Premium license..."
					Set-MgUserLicense -UserId $emailAddress -AddLicenses @{SkuId = "cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46"} -RemoveLicenses @()
				}
				"Microsoft 365 E3" {
					Write-Host "Assigning Microsoft 365 E3 license..."
					Set-MgUserLicense -UserId $emailAddress -AddLicenses @{SkuId = "05e9a617-0261-4cee-bb44-138d3ef5d965"} -RemoveLicenses @()
				}
				"Microsoft 365 E5" {
					Write-Host "Assigning Microsoft 365 E5 license..."
					Set-MgUserLicense -UserId $emailAddress -AddLicenses @{SkuId = "06ebc4ee-1bb5-47dd-8120-11324bc54e06"} -RemoveLicenses @()
				}
				Default { Write-Host "No license selected or invalid entry." }
			}
		}
		CheckForErrors
		OperationComplete
	}

	$scriptForm9 = New-Object System.Windows.Forms.Form

	$adDomainInput = New-Object System.Windows.Forms.TextBox
	$adDomainLabel = New-Object System.Windows.Forms.Label
	$emailDomainLabel = New-Object System.Windows.Forms.Label
	$emailDomainInput = New-Object System.Windows.Forms.TextBox
	$openTemplateButton = New-Object System.Windows.Forms.Button
	$createAccountsButton = New-Object System.Windows.Forms.Button
	$licenseComboBox = New-Object System.Windows.Forms.ComboBox
	$emailLicenseLabel = New-Object System.Windows.Forms.Label
	#
	# adDomainInput
	#
	$adDomainInput.Location = New-Object System.Drawing.Point(82, 10)
	$adDomainInput.Name = "adDomainInput"
	$adDomainInput.Size = New-Object System.Drawing.Size(190, 20)
	$adDomainInput.TabIndex = 1
	$adDomainInput.Text = $domain.forest
	#
	# adDomainLabel
	#
	$adDomainLabel.AutoSize = $true
	$adDomainLabel.Location = New-Object System.Drawing.Point(12, 13)
	$adDomainLabel.Name = "adDomainLabel"
	$adDomainLabel.Size = New-Object System.Drawing.Size(64, 13)
	$adDomainLabel.TabIndex = 0
	$adDomainLabel.Text = "AD Domain:"
	#
	# emailDomainLabel
	#
	$emailDomainLabel.AutoSize = $true
	$emailDomainLabel.Location = New-Object System.Drawing.Point(12, 43)
	$emailDomainLabel.Name = "emailDomainLabel"
	$emailDomainLabel.Size = New-Object System.Drawing.Size(74, 13)
	$emailDomainLabel.TabIndex = 2
	$emailDomainLabel.Text = "Email Domain:"
	#
	# emailDomainInput
	#
	$emailDomainInput.Location = New-Object System.Drawing.Point(92, 40)
	$emailDomainInput.Name = "emailDomainInput"
	$emailDomainInput.Size = New-Object System.Drawing.Size(180, 20)
	$emailDomainInput.TabIndex = 3
	$emailDomainInput.PlaceholderText = "Example: contoso.com"
	#
	# openTemplateButton
	#
	$openTemplateButton.Location = New-Object System.Drawing.Point(12, 97)
	$openTemplateButton.Name = "openTemplateButton"
	$openTemplateButton.Size = New-Object System.Drawing.Size(260, 23)
	$openTemplateButton.TabIndex = 6
	$openTemplateButton.Text = "Open Template"
	$openTemplateButton.UseVisualStyleBackColor = $true
	$openTemplateButton.Add_Click({OnOpenTemplateButtonClick})
	#
	# createAccountsButton
	#
	$createAccountsButton.Location = New-Object System.Drawing.Point(12, 126)
	$createAccountsButton.Name = "createAccountsButton"
	$createAccountsButton.Size = New-Object System.Drawing.Size(260, 23)
	$createAccountsButton.TabIndex = 7
	$createAccountsButton.Text = "Create Accounts"
	$createAccountsButton.UseVisualStyleBackColor = $true
	$createAccountsButton.Add_Click({OnCreateAccountsButtonClick})
	#
	# licenseComboBox
	#
	$licenseComboBox.FormattingEnabled = $true
	$licenseComboBox.Items.AddRange(@(
		"Exchange Online (Plan 1)",
		"Exchange Online (Plan 2)",
		"Microsoft 365 Business Basic",
		"Microsoft 365 Business Standard",
		"Microsoft 365 Business Premium",
		"Microsoft 365 E3",
		"Microsoft 365 E5"
		))
	$licenseComboBox.Location = New-Object System.Drawing.Point(93, 70)
	$licenseComboBox.Name = "licenseComboBox"
	$licenseComboBox.Size = New-Object System.Drawing.Size(179, 21)
	$licenseComboBox.TabIndex = 5
	#
	# emailLicenseLabel
	#
	$emailLicenseLabel.AutoSize = $true
	$emailLicenseLabel.Location = New-Object System.Drawing.Point(12, 73)
	$emailLicenseLabel.Name = "emailLicenseLabel"
	$emailLicenseLabel.Size = New-Object System.Drawing.Size(75, 13)
	$emailLicenseLabel.TabIndex = 4
	$emailLicenseLabel.Text = "Email License:"
	#
	# scriptForm9
	#
	$scriptForm9.ClientSize = New-Object System.Drawing.Size(284, 161)
	$scriptForm9.Controls.Add($emailLicenseLabel)
	$scriptForm9.Controls.Add($licenseComboBox)
	$scriptForm9.Controls.Add($createAccountsButton)
	$scriptForm9.Controls.Add($openTemplateButton)
	$scriptForm9.Controls.Add($emailDomainInput)
	$scriptForm9.Controls.Add($emailDomainLabel)
	$scriptForm9.Controls.Add($adDomainLabel)
	$scriptForm9.Controls.Add($adDomainInput)
	$scriptForm9.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$scriptForm9.MaximizeBox = $false
	$scriptForm9.MinimizeBox = $false
	$scriptForm9.Name = "scriptForm9"
	$scriptForm9.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$scriptForm9.Text = "New-ADAndEmailAccounts"
	$scriptForm9.Add_Shown({$scriptForm9.Activate()})

	Write-Host "Loaded ScriptForm9."
	$progressBar1.Value = 0

	$scriptForm9.ShowDialog()
	$scriptForm9.Dispose()

	Stop-Transcript
}
function New-EmailAccounts {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\New-EmailAccounts.txt"
	Write-Host "Running New-EmailAccounts script..."
	$progressBar1.Value = 10

	function OnOpenTemplateButtonClick {
		Write-Host "Open template button clicked."
		$progressBar1.Value = 10
		Invoke-Item ".\Templates\New-EmailAccounts.csv"
		$progressBar1.Value = 100
		CheckForErrors
		$progressBar1.Value = 0
	}
	function OnCreateAccountsButtonClick {
		Write-Host "createAccountsButton clicked."
		$progressBar1.Value = 10
		Import-Csv ".\Templates\New-EmailAccounts.csv" | ForEach-Object {
			$progressBar1.Value = 10
			$firstName = $_.FirstName
			$lastName = $_.LastName
			$displayName = $firstName + " " + $lastName
			$emailAddress = $_.EmailAddress
			$splitEmail = $emailAddress -split "\@"
			$mailNickname = $splitEmail[0]
			$password = $_.Password

			$passwordProfile = @{
				ForceChangePasswordNextSignIn = $false
				Password = $password
			}

			$progressBar1.Value = 30
		
			New-MgUser -AccountEnabled -PasswordProfile $passwordProfile -DisplayName $displayName -GivenName $firstName -Surname $lastName -UserPrincipalName $emailAddress -MailNickname $mailNickname -UsageLocation US
			$progressBar1.Value = 60
		
			# Set license
			switch ($licenseComboBox.Text) {
				"Exchange Online (Plan 1)" {
					Write-Host "Assigning Exchange Online (Plan 1) license..."
					Set-MgUserLicense -UserId $emailAddress -AddLicenses @{SkuId = "4b9405b0-7788-4568-add1-99614e613b69"} -RemoveLicenses @()
				}
				"Exchange Online (Plan 2)" {
					Write-Host "Assigning Exchange Online (Plan 2) license..."
					Set-MgUserLicense -UserId $emailAddress -AddLicenses @{SkuId = "19ec0d23-8335-4cbd-94ac-6050e30712fa"} -RemoveLicenses @()
				}
				"Microsoft 365 Business Basic" {
					Write-Host "Assigning Microsoft 365 Business Basic license..."
					Set-MgUserLicense -UserId $emailAddress -AddLicenses @{SkuId = "3b555118-da6a-4418-894f-7df1e2096870"} -RemoveLicenses @()
				}
				"Microsoft 365 Business Standard" {
					Write-Host "Assigning Microsoft 365 Business Standard license..."
					Set-MgUserLicense -UserId $emailAddress -AddLicenses @{SkuId = "f245ecc8-75af-4f8e-b61f-27d8114de5f3"} -RemoveLicenses @()
				}
				"Microsoft 365 Business Premium" {
					Write-Host "Assigning Microsoft 365 Business Premium license..."
					Set-MgUserLicense -UserId $emailAddress -AddLicenses @{SkuId = "cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46"} -RemoveLicenses @()
				}
				"Microsoft 365 E3" {
					Write-Host "Assigning Microsoft 365 E3 license..."
					Set-MgUserLicense -UserId $emailAddress -AddLicenses @{SkuId = "05e9a617-0261-4cee-bb44-138d3ef5d965"} -RemoveLicenses @()
				}
				"Microsoft 365 E5" {
					Write-Host "Assigning Microsoft 365 E5 license..."
					Set-MgUserLicense -UserId $emailAddress -AddLicenses @{SkuId = "06ebc4ee-1bb5-47dd-8120-11324bc54e06"} -RemoveLicenses @()
				}
				Default { Write-Host "No license selected or invalid entry." }
			}
			$progressBar1.Value = 90
		}
		CheckForErrors
		OperationComplete
	}

	$addEmailAccountsForm = New-Object System.Windows.Forms.Form

	$emailLicenseLabel = New-Object System.Windows.Forms.Label
	$licenseComboBox = New-Object System.Windows.Forms.ComboBox
	$createAccountsButton = New-Object System.Windows.Forms.Button
	$openTemplateButton = New-Object System.Windows.Forms.Button
	#
	# emailLicenseLabel
	#
	$emailLicenseLabel.AutoSize = $true
	$emailLicenseLabel.Location = New-Object System.Drawing.Point(9, 15)
	$emailLicenseLabel.Name = "emailLicenseLabel"
	$emailLicenseLabel.Size = New-Object System.Drawing.Size(75, 13)
	$emailLicenseLabel.TabIndex = 0
	$emailLicenseLabel.Text = "Email License:"
	#
	# licenseComboBox
	#
	$licenseComboBox.FormattingEnabled = $true
	$licenseComboBox.Items.AddRange(@(
		"Exchange Online (Plan 1)",
		"Exchange Online (Plan 2)",
		"Microsoft 365 Business Basic",
		"Microsoft 365 Business Standard",
		"Microsoft 365 Business Premium",
		"Microsoft 365 E3",
		"Microsoft 365 E5"
		))
	$licenseComboBox.Location = New-Object System.Drawing.Point(90, 12)
	$licenseComboBox.Name = "licenseComboBox"
	$licenseComboBox.Size = New-Object System.Drawing.Size(182, 21)
	$licenseComboBox.TabIndex = 1
	#
	# createAccountsButton
	#
	$createAccountsButton.Location = New-Object System.Drawing.Point(12, 68)
	$createAccountsButton.Name = "createAccountsButton"
	$createAccountsButton.Size = New-Object System.Drawing.Size(260, 23)
	$createAccountsButton.TabIndex = 3
	$createAccountsButton.Text = "Create Accounts"
	$createAccountsButton.UseVisualStyleBackColor = $true
	$createAccountsButton.Add_Click({OnCreateAccountsButtonClick})
	#
	# openTemplateButton
	#
	$openTemplateButton.Location = New-Object System.Drawing.Point(12, 39)
	$openTemplateButton.Name = "openTemplateButton"
	$openTemplateButton.Size = New-Object System.Drawing.Size(260, 23)
	$openTemplateButton.TabIndex = 2
	$openTemplateButton.Text = "Open Template"
	$openTemplateButton.UseVisualStyleBackColor = $true
	$openTemplateButton.Add_Click({OnOpenTemplateButtonClick})
	#
	# addEmailAccountsForm
	#
	$addEmailAccountsForm.ClientSize = New-Object System.Drawing.Size(284, 103)
	$addEmailAccountsForm.Controls.Add($emailLicenseLabel)
	$addEmailAccountsForm.Controls.Add($licenseComboBox)
	$addEmailAccountsForm.Controls.Add($createAccountsButton)
	$addEmailAccountsForm.Controls.Add($openTemplateButton)
	$addEmailAccountsForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$addEmailAccountsForm.MaximizeBox = $false
	$addEmailAccountsForm.MinimizeBox = $false
	$addEmailAccountsForm.Name = "addEmailAccountsForm"
	$addEmailAccountsForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$addEmailAccountsForm.Text = "New-EmailAccounts"
	$addEmailAccountsForm.Add_Shown({$addEmailAccountsForm.Activate()})

	Write-Host "Loaded addEmailAccountsForm."
	$progressBar1.Value = 100
	CheckForErrors
	$progressBar1.Value = 0

	$addEmailAccountsForm.ShowDialog()
	# Release the Form
	$addEmailAccountsForm.Dispose()
	
	Stop-Transcript
}
function New-InboxRule-SP {
	New-InboxRule -Name ForwardMail -Mailbox example@contoso.com -From example@contoso.com -ForwardTo example@contoso.com -MarkAsRead $true -MoveToFolder example@contoso.com:\Completed
}
function Remove-DistributionListMember {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Remove-DistributionListMember.txt"
	Write-Host "Running Remove-DistributionListMember script..."
	$progressBar1.Value = 10
	function OnRemoveMemberButtonClick {
		Write-Host "RemoveMember button clicked."
		$progressBar1.Value = 10
		$member = $memberInputBox.Text
		$group = $groupInputBox.Text
		Remove-DistributionGroupMember -Identity $group -Member $member -Confirm:$false
		Write-Host "Removing $member..."
		$progressBar1.Value = 80
		CheckForErrors
		OperationComplete
	}
	function OnOpenTemplateButtonClick {
		Write-Host "OpenTemplate button clicked."
		$progressBar1.Value = 10
		Invoke-Item ".\Templates\Remove-DistributionListMember.csv"
		$progressBar1.Value = 80
		CheckForErrors
		$progressBar1.Value = 0
	}
	function OnRemoveBulkMembersButtonClick {
		Write-Host "RemoveBulkMembers button clicked."
		$progressBar1.Value = 10
		Import-Csv ".\Templates\Remove-DistributionListMember.csv" | ForEach-Object {
			$progressBar1.Value = 20
			$member = $_.Member
			$group = $_.Group
			Remove-DistributionGroupMember -Identity $group -Member $member -Confirm:$false
			Write-Host "Removing $member ..."
			$progressBar1.Value = 80
		}
		CheckForErrors
		OperationComplete
	}

	$scriptForm8 = New-Object System.Windows.Forms.Form

	$groupBox1 = New-Object System.Windows.Forms.GroupBox
	$memberInputBox = New-Object System.Windows.Forms.TextBox
	$label1 = New-Object System.Windows.Forms.Label
	$groupInputBox = New-Object System.Windows.Forms.TextBox
	$label2 = New-Object System.Windows.Forms.Label
	$removeMemberButton = New-Object System.Windows.Forms.Button
	$groupBox2 = New-Object System.Windows.Forms.GroupBox
	$openTemplateButton = New-Object System.Windows.Forms.Button
	$removeBulkMembersButton = New-Object System.Windows.Forms.Button
	#
	# groupBox1
	#
	$groupBox1.Controls.Add($removeMemberButton)
	$groupBox1.Controls.Add($label2)
	$groupBox1.Controls.Add($groupInputBox)
	$groupBox1.Controls.Add($label1)
	$groupBox1.Controls.Add($memberInputBox)
	$groupBox1.Location = New-Object System.Drawing.Point(12, 12)
	$groupBox1.Name = "groupBox1"
	$groupBox1.Size = New-Object System.Drawing.Size(266, 100)
	$groupBox1.TabIndex = 0
	$groupBox1.TabStop = $false
	$groupBox1.Text = "Single"
	#
	# textBox1
	#
	$memberInputBox.Location = New-Object System.Drawing.Point(60, 19)
	$memberInputBox.Name = "textBox1"
	$memberInputBox.Size = New-Object System.Drawing.Size(200, 20)
	$memberInputBox.TabIndex = 0
	#
	# label1
	#
	$label1.AutoSize = $true
	$label1.Location = New-Object System.Drawing.Point(6, 22)
	$label1.Name = "label1"
	$label1.Size = New-Object System.Drawing.Size(48, 13)
	$label1.TabIndex = 0
	$label1.Text = "Member:"
	#
	# textBox2
	#
	$groupInputBox.Location = New-Object System.Drawing.Point(60, 45)
	$groupInputBox.Name = "textBox2"
	$groupInputBox.Size = New-Object System.Drawing.Size(200, 20)
	$groupInputBox.TabIndex = 1
	#
	# label2
	#
	$label2.AutoSize = $true
	$label2.Location = New-Object System.Drawing.Point(6, 48)
	$label2.Name = "label2"
	$label2.Size = New-Object System.Drawing.Size(39, 13)
	$label2.TabIndex = 1
	$label2.Text = "Group:"
	#
	# removeMemberButton
	#
	$removeMemberButton.Location = New-Object System.Drawing.Point(6, 71)
	$removeMemberButton.Name = "removeMemberButton"
	$removeMemberButton.Size = New-Object System.Drawing.Size(254, 23)
	$removeMemberButton.TabIndex = 2
	$removeMemberButton.Text = "Remove Member"
	$removeMemberButton.UseVisualStyleBackColor = $true
	$removeMemberButton.Add_Click({OnRemoveMemberButtonClick})
	#
	# groupBox2
	#
	$groupBox2.Controls.Add($removeBulkMembersButton)
	$groupBox2.Controls.Add($openTemplateButton)
	$groupBox2.Location = New-Object System.Drawing.Point(12, 118)
	$groupBox2.Name = "groupBox2"
	$groupBox2.Size = New-Object System.Drawing.Size(266, 77)
	$groupBox2.TabIndex = 3
	$groupBox2.TabStop = $false
	$groupBox2.Text = "Bulk"
	#
	# openTemplateButton
	#
	$openTemplateButton.Location = New-Object System.Drawing.Point(6, 19)
	$openTemplateButton.Name = "openTemplateButton"
	$openTemplateButton.Size = New-Object System.Drawing.Size(254, 23)
	$openTemplateButton.TabIndex = 3
	$openTemplateButton.Text = "Open Template"
	$openTemplateButton.UseVisualStyleBackColor = $true
	$openTemplateButton.Add_Click({OnOpenTemplateButtonClick})
	#
	# removeBulkMembersButton
	#
	$removeBulkMembersButton.Location = New-Object System.Drawing.Point(6, 48)
	$removeBulkMembersButton.Name = "removeBulkMembersButton"
	$removeBulkMembersButton.Size = New-Object System.Drawing.Size(254, 23)
	$removeBulkMembersButton.TabIndex = 4
	$removeBulkMembersButton.Text = "Remove Members"
	$removeBulkMembersButton.UseVisualStyleBackColor = $true
	$removeBulkMembersButton.Add_Click({OnRemoveBulkMembersButtonClick})
	#
	# scriptForm8
	#
	$scriptForm8.ClientSize = New-Object System.Drawing.Size(290, 207)
	$scriptForm8.Controls.Add($groupBox2)
	$scriptForm8.Controls.Add($groupBox1)
	$scriptForm8.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$scriptForm8.HelpButton = $false
	$scriptForm8.MaximizeBox = $false
	$scriptForm8.MinimizeBox = $false
	$scriptForm8.Name = "scriptForm8"
	$scriptForm8.ShowIcon = $false
	$scriptForm8.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$scriptForm8.Text = "Remove-DistributionListMember"
	$scriptForm8.Add_Shown({$scriptForm8.Activate()})

	Write-Host "Loaded ScriptForm8."
	$progressBar1.Value = 0

	$scriptForm8.ShowDialog()
	$scriptForm8.Dispose()

	Stop-Transcript
}
function Remove-EmailAlias {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Remove-EmailAlias.txt"
	Write-Host "Running Remove-EmailAlias script..."
	$progressBar1.Value = 10

	function OnRemoveAliasButtonClick {
		Write-Host "removeAliasButton clicked."
		switch ($incrementalCheckBox.Checked) {
			$true {
				Write-Host "Removing incremental aliases..."
				$progressBar1.Value = 10
				$mailbox = $mailboxTextBox.Text
				$alias = $aliasTextBox.Text
				$splitAlias = $alias -split '\@'
				$aliasName = $splitAlias[0]
				$aliasDomain = $splitAlias[1]
				$progressBar1.Value = 30
				for ($i = 0; $i -lt $numericUpDown1.Value; $i++) {
					$progressBar1.Value = 10
					$completeAlias = $aliasName + [string]$i + "@" + $aliasDomain
					Set-Mailbox $mailbox -EmailAddresses @{Remove= $completeAlias}
					Write-Host "Removed $completeAlias from $mailbox."
					$progressBar1.Value = 90
				}
				$progressBar1.Value = 90
				CheckForErrors
				OperationComplete
			}
			$false {
				Write-Host "Removing single alias..."
				$progressBar1.Value = 10
				$mailbox = $mailboxTextBox.Text
				$alias = $aliasTextBox.Text
				$progressBar1.Value = 30
				Set-Mailbox $mailbox -EmailAddresses @{Remove= $alias}
				$progressBar1.Value = 50
				Write-Host "Removed $alias from $mailbox."
				$progressBar1.Value = 80
				CheckForErrors
				OperationComplete
			}
			Default {
				Write-Host "An error seems to have occurred."
				CheckForErrors
			}
		}
	}
	function OnOpenTemplateButtonClick {
		$progressBar1.Value = 10
		Invoke-Item ".\Templates\Remove-EmailAlias.csv"
		$progressBar1.Value = 100
		CheckForErrors
		$progressBar1.Value = 0
	}
	function OnRemoveAliasBulkButtonClick {
		Import-Csv ".\Templates\Remove-EmailAlias.csv" | ForEach-Object {
			$progressBar1.Value = 20
			$mailbox = $_.Mailbox
			$alias = $_.Alias
			$progressBar1.Value = 50
			Set-Mailbox $mailbox -EmailAddresses @{Remove= $alias}
			Write-Host "Removed $alias from $mailbox."
			$progressBar1.Value = 80
		}
		CheckForErrors
		OperationComplete
	}
	function OnIncrementalCheckBoxChecked {
		if ($incrementalCheckBox.Checked -eq $true) {
			$numericUpDown1.Enabled = $true
			$removeAliasButton.Text = "Remove Aliases"
		} elseif ($incrementalCheckBox.Checked -eq $false) {
			$numericUpDown1.Enabled = $false
			$removeAliasButton.Text = "Remove Alias"
		}
	}
	function OnGetAliasButtonClick {
		Write-Host "GetAliasButton clicked."
		$progressBar1.Value = 10
		$infoTextBox.Text = Get-Mailbox $mailboxTextBox.Text | Select-Object -ExpandProperty emailaddresses
		$progressBar1.Value = 80
		CheckForErrors
		$progressBar1.Value = 0
	}
	function OnCopyButtonClick {
		Write-Host "CopyButton clicked."
		$progressBar1.Value = 10
		Get-Mailbox $mailboxTextBox.Text | Select-Object -ExpandProperty emailaddresses | Set-Clipboard
		$progressBar1.Value = 80
		CheckForErrors
		OperationComplete
	}

	$emailAliasForm = New-Object System.Windows.Forms.Form

	$groupBox1 = New-Object System.Windows.Forms.GroupBox
	$removeAliasButton = New-Object System.Windows.Forms.Button
	$aliasLabel = New-Object System.Windows.Forms.Label
	$aliasTextBox = New-Object System.Windows.Forms.TextBox
	$mailboxLabel = New-Object System.Windows.Forms.Label
	$mailboxTextBox = New-Object System.Windows.Forms.TextBox
	$groupBox2 = New-Object System.Windows.Forms.GroupBox
	$removeAliasBulkButton = New-Object System.Windows.Forms.Button
	$openTemplateButton = New-Object System.Windows.Forms.Button
	$groupBox3 = New-Object System.Windows.Forms.GroupBox
	$getAliasButton = New-Object System.Windows.Forms.Button
	$infoTextBox = New-Object System.Windows.Forms.TextBox
	$copyButton = New-Object System.Windows.Forms.Button
	$incrementalCheckBox = New-Object System.Windows.Forms.CheckBox
	$numericUpDown1 = New-Object System.Windows.Forms.NumericUpDown
	#
	# groupBox1
	#
	$groupBox1.Controls.Add($numericUpDown1)
	$groupBox1.Controls.Add($incrementalCheckBox)
	$groupBox1.Controls.Add($removeAliasButton)
	$groupBox1.Controls.Add($aliasLabel)
	$groupBox1.Controls.Add($aliasTextBox)
	$groupBox1.Controls.Add($mailboxLabel)
	$groupBox1.Controls.Add($mailboxTextBox)
	$groupBox1.Location = New-Object System.Drawing.Point(12, 12)
	$groupBox1.Name = "groupBox1"
	$groupBox1.Size = New-Object System.Drawing.Size(260, 147)
	$groupBox1.TabIndex = 0
	$groupBox1.TabStop = $false
	$groupBox1.Text = "Single"
	#
	# removeAliasButton
	#
	$removeAliasButton.Location = New-Object System.Drawing.Point(6, 99)
	$removeAliasButton.Name = "removeAliasButton"
	$removeAliasButton.Size = New-Object System.Drawing.Size(248, 23)
	$removeAliasButton.TabIndex = 7
	$removeAliasButton.Text = "Remove Alias"
	$removeAliasButton.UseVisualStyleBackColor = $true
	$removeAliasButton.Add_Click({OnRemoveAliasButtonClick})
	#
	# aliasLabel
	#
	$aliasLabel.AutoSize = $true
	$aliasLabel.Location = New-Object System.Drawing.Point(6, 48)
	$aliasLabel.Name = "aliasLabel"
	$aliasLabel.Size = New-Object System.Drawing.Size(32, 13)
	$aliasLabel.TabIndex = 3
	$aliasLabel.Text = "Alias:"
	#
	# aliasTextBox
	#
	$aliasTextBox.Location = New-Object System.Drawing.Point(58, 45)
	$aliasTextBox.Name = "aliasTextBox"
	$aliasTextBox.Size = New-Object System.Drawing.Size(196, 20)
	$aliasTextBox.TabIndex = 4
	#
	# mailboxLabel
	#
	$mailboxLabel.AutoSize = $true
	$mailboxLabel.Location = New-Object System.Drawing.Point(6, 22)
	$mailboxLabel.Name = "mailboxLabel"
	$mailboxLabel.Size = New-Object System.Drawing.Size(46, 13)
	$mailboxLabel.TabIndex = 1
	$mailboxLabel.Text = "Mailbox:"
	#
	# mailboxTextBox
	#
	$mailboxTextBox.Location = New-Object System.Drawing.Point(58, 19)
	$mailboxTextBox.Name = "mailboxTextBox"
	$mailboxTextBox.Size = New-Object System.Drawing.Size(196, 20)
	$mailboxTextBox.TabIndex = 2
	#
	# groupBox2
	#
	$groupBox2.Controls.Add($removeAliasBulkButton)
	$groupBox2.Controls.Add($openTemplateButton)
	$groupBox2.Location = New-Object System.Drawing.Point(12, 165)
	$groupBox2.Name = "groupBox2"
	$groupBox2.Size = New-Object System.Drawing.Size(260, 77)
	$groupBox2.TabIndex = 8
	$groupBox2.TabStop = $false
	$groupBox2.Text = "Bulk"
	#
	# removeAliasBulkButton
	#
	$removeAliasBulkButton.Location = New-Object System.Drawing.Point(6, 48)
	$removeAliasBulkButton.Name = "removeAliasBulkButton"
	$removeAliasBulkButton.Size = New-Object System.Drawing.Size(248, 23)
	$removeAliasBulkButton.TabIndex = 10
	$removeAliasBulkButton.Text = "Remove Aliases"
	$removeAliasBulkButton.UseVisualStyleBackColor = $true
	$removeAliasBulkButton.Add_Click({OnRemoveAliasBulkButtonClick})
	#
	# openTemplateButton
	#
	$openTemplateButton.Location = New-Object System.Drawing.Point(6, 19)
	$openTemplateButton.Name = "openTemplateButton"
	$openTemplateButton.Size = New-Object System.Drawing.Size(248, 23)
	$openTemplateButton.TabIndex = 9
	$openTemplateButton.Text = "Open Template"
	$openTemplateButton.UseVisualStyleBackColor = $true
	$openTemplateButton.Add_Click({OnOpenTemplateButtonClick})
	#
	# groupBox3
	#
	$groupBox3.Controls.Add($copyButton)
	$groupBox3.Controls.Add($infoTextBox)
	$groupBox3.Controls.Add($getAliasButton)
	$groupBox3.Location = New-Object System.Drawing.Point(278, 12)
	$groupBox3.Name = "groupBox3"
	$groupBox3.Size = New-Object System.Drawing.Size(260, 230)
	$groupBox3.TabIndex = 11
	$groupBox3.TabStop = $false
	$groupBox3.Text = "Info"
	#
	# getAliasButton
	#
	$getAliasButton.Location = New-Object System.Drawing.Point(6, 19)
	$getAliasButton.Name = "getAliasButton"
	$getAliasButton.Size = New-Object System.Drawing.Size(248, 23)
	$getAliasButton.TabIndex = 12
	$getAliasButton.Text = "Get Current Aliases"
	$getAliasButton.UseVisualStyleBackColor = $true
	$getAliasButton.Add_Click({OnGetAliasButtonClick})
	#
	# infoTextBox
	#
	$infoTextBox.Location = New-Object System.Drawing.Point(6, 48)
	$infoTextBox.Multiline = $true
	$infoTextBox.Name = "infoTextBox"
	$infoTextBox.ReadOnly = $true
	$infoTextBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
	$infoTextBox.Size = New-Object System.Drawing.Size(248, 147)
	$infoTextBox.TabIndex = 13
	#
	# copyButton
	#
	$copyButton.Location = New-Object System.Drawing.Point(6, 201)
	$copyButton.Name = "copyButton"
	$copyButton.Size = New-Object System.Drawing.Size(248, 23)
	$copyButton.TabIndex = 14
	$copyButton.Text = "Copy to Clipboard"
	$copyButton.UseVisualStyleBackColor = $true
	$copyButton.Add_Click({OnCopyButtonClick})
	#
	# incrementalCheckBox
	#
	$incrementalCheckBox.AutoSize = $true
	$incrementalCheckBox.Location = New-Object System.Drawing.Point(9, 74)
	$incrementalCheckBox.Name = "incrementalCheckBox"
	$incrementalCheckBox.Size = New-Object System.Drawing.Size(130, 17)
	$incrementalCheckBox.TabIndex = 5
	$incrementalCheckBox.Text = "Remove Incremental Aliases"
	$incrementalCheckBox.UseVisualStyleBackColor = $true
	$incrementalCheckBox.Add_CheckedChanged({OnIncrementalCheckBoxChecked})
	#
	# numericUpDown1
	#
	$numericUpDown1.Enabled = $false
	$numericUpDown1.Location = New-Object System.Drawing.Point(166, 73)
	#$numericUpDown1.Maximum = New-Object decimal(@(
	#1000,
	#0,
	#0,
	#0))
	$numericUpDown1.Name = "numericUpDown1"
	$numericUpDown1.Size = New-Object System.Drawing.Size(88, 20)
	$numericUpDown1.TabIndex = 6
	#
	# emailAliasForm
	#
	$emailAliasForm.ClientSize = New-Object System.Drawing.Size(550, 254)
	$emailAliasForm.Controls.Add($groupBox3)
	$emailAliasForm.Controls.Add($groupBox1)
	$emailAliasForm.Controls.Add($groupBox2)
	$emailAliasForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$emailAliasForm.MaximizeBox = $false
	$emailAliasForm.MinimizeBox = $false
	$emailAliasForm.Name = "emailAliasForm"
	$emailAliasForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$emailAliasForm.Text = "Remove-EmailAlias"

	$emailAliasForm.Add_Shown({$emailAliasForm.Activate()})

	$progressBar1.Value = 100
	Write-Host "Loaded EmailAliasForm."
	$progressBar1.Value = 0

	$emailAliasForm.ShowDialog()
	$emailAliasForm.Dispose()

	Stop-Transcript
}
function Remove-UnifiedGroupMember {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Remove-UnifiedGroupMember.txt"
	Write-Host "Running Remove-UnifiedGroupMember script..."
	$progressBar1.Value = 10
	function OnRemoveMemberButtonClick {
		Write-Host "RemoveMember button clicked."
		$progressBar1.Value = 10
		$member = $memberInputBox.Text
		$group = $groupInputBox.Text
		Remove-UnifiedGroupLinks -Identity $group -LinkType Members -Links $member -Confirm:$false
		Write-Host "Removing $member..."
		$progressBar1.Value = 80
		CheckForErrors
		OperationComplete
	}
	function OnOpenTemplateButtonClick {
		Write-Host "OpenTemplate button clicked."
		$progressBar1.Value = 10
		Invoke-Item ".\Templates\Remove-UnifiedGroupMember.csv"
		$progressBar1.Value = 80
		CheckForErrors
		$progressBar1.Value = 0
	}
	function OnRemoveBulkMembersButtonClick {
		Write-Host "RemoveBulkMembers button clicked."
		$progressBar1.Value = 10
		Import-Csv ".\Templates\Remove-UnifiedGroupMember.csv" | ForEach-Object {
			$progressBar1.Value = 20
			$member = $_.Member
			$group = $_.Group
			Remove-UnifiedGroupLinks -Identity $group -LinkType Members -Links $member -Confirm:$false
			Write-Host "Remove $member ..."
			$progressBar1.Value = 80
		}
		CheckForErrors
		OperationComplete
	}

	$scriptForm8 = New-Object System.Windows.Forms.Form

	$groupBox1 = New-Object System.Windows.Forms.GroupBox
	$memberInputBox = New-Object System.Windows.Forms.TextBox
	$label1 = New-Object System.Windows.Forms.Label
	$groupInputBox = New-Object System.Windows.Forms.TextBox
	$label2 = New-Object System.Windows.Forms.Label
	$removeMemberButton = New-Object System.Windows.Forms.Button
	$groupBox2 = New-Object System.Windows.Forms.GroupBox
	$openTemplateButton = New-Object System.Windows.Forms.Button
	$removeBulkMembersButton = New-Object System.Windows.Forms.Button
	#
	# groupBox1
	#
	$groupBox1.Controls.Add($removeMemberButton)
	$groupBox1.Controls.Add($label2)
	$groupBox1.Controls.Add($groupInputBox)
	$groupBox1.Controls.Add($label1)
	$groupBox1.Controls.Add($memberInputBox)
	$groupBox1.Location = New-Object System.Drawing.Point(12, 12)
	$groupBox1.Name = "groupBox1"
	$groupBox1.Size = New-Object System.Drawing.Size(266, 100)
	$groupBox1.TabIndex = 0
	$groupBox1.TabStop = $false
	$groupBox1.Text = "Single"
	#
	# textBox1
	#
	$memberInputBox.Location = New-Object System.Drawing.Point(60, 19)
	$memberInputBox.Name = "textBox1"
	$memberInputBox.Size = New-Object System.Drawing.Size(200, 20)
	$memberInputBox.TabIndex = 0
	#
	# label1
	#
	$label1.AutoSize = $true
	$label1.Location = New-Object System.Drawing.Point(6, 22)
	$label1.Name = "label1"
	$label1.Size = New-Object System.Drawing.Size(48, 13)
	$label1.TabIndex = 0
	$label1.Text = "Member:"
	#
	# textBox2
	#
	$groupInputBox.Location = New-Object System.Drawing.Point(60, 45)
	$groupInputBox.Name = "textBox2"
	$groupInputBox.Size = New-Object System.Drawing.Size(200, 20)
	$groupInputBox.TabIndex = 1
	#
	# label2
	#
	$label2.AutoSize = $true
	$label2.Location = New-Object System.Drawing.Point(6, 48)
	$label2.Name = "label2"
	$label2.Size = New-Object System.Drawing.Size(39, 13)
	$label2.TabIndex = 1
	$label2.Text = "Group:"
	#
	# addMemberButton
	#
	$removeMemberButton.Location = New-Object System.Drawing.Point(6, 71)
	$removeMemberButton.Name = "removeMemberButton"
	$removeMemberButton.Size = New-Object System.Drawing.Size(254, 23)
	$removeMemberButton.TabIndex = 2
	$removeMemberButton.Text = "Remove Member"
	$removeMemberButton.UseVisualStyleBackColor = $true
	$removeMemberButton.Add_Click({OnRemoveMemberButtonClick})
	#
	# groupBox2
	#
	$groupBox2.Controls.Add($removeBulkMembersButton)
	$groupBox2.Controls.Add($openTemplateButton)
	$groupBox2.Location = New-Object System.Drawing.Point(12, 118)
	$groupBox2.Name = "groupBox2"
	$groupBox2.Size = New-Object System.Drawing.Size(266, 77)
	$groupBox2.TabIndex = 3
	$groupBox2.TabStop = $false
	$groupBox2.Text = "Bulk"
	#
	# openTemplateButton
	#
	$openTemplateButton.Location = New-Object System.Drawing.Point(6, 19)
	$openTemplateButton.Name = "openTemplateButton"
	$openTemplateButton.Size = New-Object System.Drawing.Size(254, 23)
	$openTemplateButton.TabIndex = 3
	$openTemplateButton.Text = "Open Template"
	$openTemplateButton.UseVisualStyleBackColor = $true
	$openTemplateButton.Add_Click({OnOpenTemplateButtonClick})
	#
	# addBulkMembersButton
	#
	$removeBulkMembersButton.Location = New-Object System.Drawing.Point(6, 48)
	$removeBulkMembersButton.Name = "removeBulkMembersButton"
	$removeBulkMembersButton.Size = New-Object System.Drawing.Size(254, 23)
	$removeBulkMembersButton.TabIndex = 4
	$removeBulkMembersButton.Text = "Remove Members"
	$removeBulkMembersButton.UseVisualStyleBackColor = $true
	$removeBulkMembersButton.Add_Click({OnRemoveBulkMembersButtonClick})
	#
	# scriptForm8
	#
	$scriptForm8.ClientSize = New-Object System.Drawing.Size(290, 207)
	$scriptForm8.Controls.Add($groupBox2)
	$scriptForm8.Controls.Add($groupBox1)
	$scriptForm8.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$scriptForm8.HelpButton = $false
	$scriptForm8.MaximizeBox = $false
	$scriptForm8.MinimizeBox = $false
	$scriptForm8.Name = "scriptForm8"
	$scriptForm8.ShowIcon = $false
	$scriptForm8.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$scriptForm8.Text = "Remove-UnifiedGroupMember"
	$scriptForm8.Add_Shown({$scriptForm8.Activate()})

	Write-Host "Loaded ScriptForm8."
	$progressBar1.Value = 0

	$scriptForm8.ShowDialog()
	$scriptForm8.Dispose()

	Stop-Transcript
}
function Revoke-AllSignInSessions {
	$userIds = Get-MgUser -All | Select-Object ID
	foreach($userId in $userIds) {
		Revoke-MgUserSignInSession -UserId $userId.Id
	}
}
function Update-ScriptPackage {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Update-ScriptPackage.txt"
	Write-Host "Running Update-ScriptPackage script..."
	$progressBar1.Value = 10
	$versionCheck = Invoke-WebRequest -Uri "https://github.com/DiadNetworks/Script-Package/releases/latest"
	$versionLink = $versionCheck.Links.href | Where-Object {
		$_ -Like "*/releases/tag/v*"
	}
	$splitLink = $versionLink -Split 'tag/'
	$remoteVersion = $splitLink[1]
	$progressBar1.Value = 30
	
	$updateCompleteForm = New-Object System.Windows.Forms.Form
	
	$closeUpdateFormButton = New-Object System.Windows.Forms.Button
	#
	# closeUpdateFormButton
	#
	$closeUpdateFormButton.Location = New-Object System.Drawing.Point(105, 44)
	$closeUpdateFormButton.Name = "closeUpdateFormButton"
	$closeUpdateFormButton.Size = New-Object System.Drawing.Size(75, 23)
	$closeUpdateFormButton.TabIndex = 0
	$closeUpdateFormButton.Text = "COOL!"
	$closeUpdateFormButton.UseVisualStyleBackColor = $true
	$closeUpdateFormButton.Add_Click({
		$progressBar1.Value = 0
		$updateCompleteForm.Close()
		$updateCompleteForm.Dispose()
		Write-Host "Closed UpdateComplete form."
	})
	#
	# updateCompleteForm
	#
	$updateCompleteForm.AcceptButton = $closeUpdateFormButton
	$updateCompleteForm.ClientSize = New-Object System.Drawing.Size(284, 111)
	$updateCompleteForm.Controls.Add($closeUpdateFormButton)
	$updateCompleteForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
	$updateCompleteForm.MaximizeBox = $false
	$updateCompleteForm.MinimizeBox = $false
	$updateCompleteForm.Name = "updateCompleteForm"
	$updateCompleteForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$updateCompleteForm.Text = ""

	if ($remoteVersion -eq $version) {
		Write-Host "Latest version of Script-Package already installed."
		$updateCompleteForm.Text = "Latest version already installed."
		$progressBar1.Value = 100
		CheckForErrors
		$progressBar1.Value = 0
		$updateCompleteForm.ShowDialog()
	} else {
		Write-Host "Downloading latest version of Script-Package..."
		Invoke-WebRequest -Uri "https://github.com/DiadNetworks/Script-Package/releases/latest/download/Script-Package-Setup.exe" -OutFile "$env:TEMP\Script-Package-Setup.exe"
		$progressBar1.Value = 50
		Write-Host "Launching downloaded file..."
		Start-Process "$env:TEMP\Script-Package-Setup.exe" -ArgumentList "/SP-", "/SILENT" -Wait
		$progressBar1.Value = 70
		CheckForErrors
		$updateCompleteForm.Text = "Installed latest version, enjoy!"
		$progressBar1.Value = 100
		$updateCompleteForm.ShowDialog()
	}
	Stop-Transcript
}
function Set-ACLPermissions {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Set-ACLPermissions.txt"
	Write-Host "Running Set-ACLPermissions script..."
	$progressBar1.Value = 10
	function ToggleSingleMultiple {
		if ($singleRadioButton.Checked) {
			Write-Host "singleRadioButton is checked."
			$pathTextBox.Enabled = $true
			$openTemplateButton.Enabled = $false
		} elseif ($multipleRadioButton.Checked) {
			Write-Host "multipleRadioButton is checked."
			$pathTextBox.Enabled = $false
			$openTemplateButton.Enabled = $true
		} else {
			Write-Host "Error, both radio buttons unchecked."
		}
	}
	function OnOpenTemplateButtonClick {
		Write-Host "openTemplateButton clicked."
		$continuousProgressBar.Value = 10
		Invoke-Item ".\Templates\Set-ACLPermissions.txt"
		$continuousProgressBar.Value = 100
		CheckForErrors
		$continuousProgressBar.Value = 0
	}
	function OnRightsHelpButtonClick {
		Write-Host "rightsHelpButton clicked."
		$continuousProgressBar.Value = 10
		Start-Process "https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights?view=net-7.0"
		$continuousProgressBar.Value = 100
		CheckForErrors
		$continuousProgressBar.Value = 0
	}
	function OnSetPermissionsButtonClick {
		Write-Host "setPermissionsButton clicked."
		$continuousProgressBar.Value = 10
	
		if ($singleRadioButton.Checked) {
			$aclPath = $pathTextBox.Text
			$acl = Get-Acl $aclPath
			$identity = "$domainName\$($userGroupComboBox.Text)"
			$continuousProgressBar.Value = 20
	
			$rights = ""
			foreach ($item in $rightsCheckedListBox.CheckedItems) {
				$rights += $item.ToString() + ","
			}
			$rights = $rights.TrimEnd(',')
			$continuousProgressBar.Value = 30
	
			$inheritanceFlags = ""
			foreach ($item in $inheritanceCheckedListBox.CheckedItems) {
				$inheritanceFlags += $item.ToString() + ","
			}
			$inheritanceFlags = $inheritanceFlags.TrimEnd(',')
			$continuousProgressBar.Value = 40
	
			$propagationFlags = ""
			foreach ($item in $propagationCheckedListBox.CheckedItems) {
				$propagationFlags += $item.ToString() + ","
			}
			$propagationFlags = $propagationFlags.TrimEnd(',')
			$continuousProgressBar.Value = 50
	
			if ($actAllowRadioButton) {
				Write-Host "actAllowRadioButton is checked."
				$accessControlType = "Allow"
			} elseif ($actDenyRadioButton) {
				Write-Host "actDenyRadioButton is checked."
				$accessControlType = "Deny"
			} else {
				Write-Host "Error, both radio buttons unchecked."
			}
			$continuousProgressBar.Value = 60
	
			$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$identity","$rights","$inheritanceFlags","$propagationFlags","$accessControlType")
			$acl.AddAccessRule($rule)
			Set-Acl $aclPath $acl
			$continuousProgressBar.Value = 100
			$continuousProgressBar.Value = 0
		} elseif ($multipleRadioButton.Checked) {
			$identity = "$domainName\$($userGroupComboBox.Text)"
			$continuousProgressBar.Value = 10
	
			$rights = ""
			foreach ($item in $rightsCheckedListBox.CheckedItems) {
				$rights += $item.ToString() + ","
			}
			$rights = $rights.TrimEnd(',')
			$continuousProgressBar.Value = 20
	
			$inheritanceFlags = ""
			foreach ($item in $inheritanceCheckedListBox.CheckedItems) {
				$inheritanceFlags += $item.ToString() + ","
			}
			$inheritanceFlags = $inheritanceFlags.TrimEnd(',')
			$continuousProgressBar.Value = 30
	
			$propagationFlags = ""
			foreach ($item in $propagationCheckedListBox.CheckedItems) {
				$propagationFlags += $item.ToString() + ","
			}
			$propagationFlags = $propagationFlags.TrimEnd(',')
			$continuousProgressBar.Value = 40
	
			if ($actAllowRadioButton) {
				Write-Host "actAllowRadioButton is checked."
				$accessControlType = "Allow"
			} elseif ($actDenyRadioButton) {
				Write-Host "actDenyRadioButton is checked."
				$accessControlType = "Deny"
			} else {
				Write-Host "Error, both radio buttons unchecked."
			}
			$continuousProgressBar.Value = 50
			Get-Content ".\Templates\Set-ACLPermissions.txt" | ForEach-Object {
				$continuousProgressBar.Value = 60
				$aclPath = $_
				$acl = Get-Acl $aclPath
				$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$identity","$rights","$inheritanceFlags","$propagationFlags","$accessControlType")
				$acl.AddAccessRule($rule)
				Set-Acl $aclPath $acl
				$continuousProgressBar.Value = 80
			}
			$continuousProgressBar.Value = 100
			$continuousProgressBar.Value = 0
		} else {
			Write-Host "Error, both radio buttons unchecked."
		}
		CheckForErrors
		OperationComplete
	}
	
	$domainName = (Get-ciminstance -Class Win32_UserAccount -Filter "Name='$env:USERNAME'").Domain
	
	$allUsers = Get-ADUser -Filter * -Properties SamAccountName | Sort-Object SamAccountName
	$allGroups = Get-ADGroup -Filter * -Properties Name | Sort-Object Name
	$fullList = $allUsers.SamAccountName + $allGroups.Name

	$setPermissionsForm = New-Object System.Windows.Forms.Form
	
	$identityGroupBox = New-Object System.Windows.Forms.GroupBox
	$userGroupLabel = New-Object System.Windows.Forms.Label
	$domainTextBox = New-Object System.Windows.Forms.TextBox
	$domainLabel = New-Object System.Windows.Forms.Label
	$rightsGroupBox = New-Object System.Windows.Forms.GroupBox
	$rightsHelpButton = New-Object System.Windows.Forms.Button
	$rightsCheckedListBox = New-Object System.Windows.Forms.CheckedListBox
	$fileGroupBox = New-Object System.Windows.Forms.GroupBox
	$multipleRadioButton = New-Object System.Windows.Forms.RadioButton
	$singleRadioButton = New-Object System.Windows.Forms.RadioButton
	$pathLabel = New-Object System.Windows.Forms.Label
	$pathTextBox = New-Object System.Windows.Forms.TextBox
	$openTemplateButton = New-Object System.Windows.Forms.Button
	$inheritanceGroupBox = New-Object System.Windows.Forms.GroupBox
	$inheritanceCheckedListBox = New-Object System.Windows.Forms.CheckedListBox
	$propagationGroupBox = New-Object System.Windows.Forms.GroupBox
	$propagationCheckedListBox = New-Object System.Windows.Forms.CheckedListBox
	$actGroupBox = New-Object System.Windows.Forms.GroupBox
	$actAllowRadioButton = New-Object System.Windows.Forms.RadioButton
	$actDenyRadioButton = New-Object System.Windows.Forms.RadioButton
	$userGroupComboBox = New-Object System.Windows.Forms.ComboBox
	$continuousProgressBar = New-Object System.Windows.Forms.ProgressBar
	$setPermissionsButton = New-Object System.Windows.Forms.Button
	#
	# identityGroupBox
	#
	$identityGroupBox.Controls.Add($userGroupComboBox)
	$identityGroupBox.Controls.Add($userGroupLabel)
	$identityGroupBox.Controls.Add($domainTextBox)
	$identityGroupBox.Controls.Add($domainLabel)
	$identityGroupBox.Location = New-Object System.Drawing.Point(12, 89)
	$identityGroupBox.Name = "identityGroupBox"
	$identityGroupBox.Size = New-Object System.Drawing.Size(460, 70)
	$identityGroupBox.TabIndex = 6
	$identityGroupBox.TabStop = $false
	$identityGroupBox.Text = "Identity"
	#
	# userGroupLabel
	#
	$userGroupLabel.AutoSize = $true
	$userGroupLabel.Location = New-Object System.Drawing.Point(7, 47)
	$userGroupLabel.Name = "userGroupLabel"
	$userGroupLabel.Size = New-Object System.Drawing.Size(66, 13)
	$userGroupLabel.TabIndex = 9
	$userGroupLabel.Text = "User/Group:"
	#
	# domainTextBox
	#
	$domainTextBox.Location = New-Object System.Drawing.Point(59, 17)
	$domainTextBox.Name = "domainTextBox"
	$domainTextBox.Size = New-Object System.Drawing.Size(395, 20)
	$domainTextBox.TabIndex = 8
	$domainTextBox.Text = $domainName
	#
	# domainLabel
	#
	$domainLabel.AutoSize = $true
	$domainLabel.Location = New-Object System.Drawing.Point(7, 20)
	$domainLabel.Name = "domainLabel"
	$domainLabel.Size = New-Object System.Drawing.Size(46, 13)
	$domainLabel.TabIndex = 7
	$domainLabel.Text = "Domain:"
	#
	# rightsGroupBox
	#
	$rightsGroupBox.Controls.Add($rightsHelpButton)
	$rightsGroupBox.Controls.Add($rightsCheckedListBox)
	$rightsGroupBox.Location = New-Object System.Drawing.Point(12, 165)
	$rightsGroupBox.Name = "rightsGroupBox"
	$rightsGroupBox.Size = New-Object System.Drawing.Size(200, 285)
	$rightsGroupBox.TabIndex = 11
	$rightsGroupBox.TabStop = $false
	$rightsGroupBox.Text = "Rights"
	#
	# rightsHelpButton
	#
	$rightsHelpButton.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 8.25,[System.Drawing.FontStyle]::Underline,[System.Drawing.GraphicsUnit]::Point, 0)
	$rightsHelpButton.Location = New-Object System.Drawing.Point(6, 255)
	$rightsHelpButton.Name = "rightsHelpButton"
	$rightsHelpButton.Size = New-Object System.Drawing.Size(188, 23)
	$rightsHelpButton.TabIndex = 13
	$rightsHelpButton.Text = "Help"
	$rightsHelpButton.UseVisualStyleBackColor = $true
	$rightsHelpButton.Add_Click({OnRightsHelpButtonClick})
	#
	# rightsCheckedListBox
	#
	$rightsCheckedListBox.CheckOnClick = $true
	$rightsCheckedListBox.FormattingEnabled = $true
	$rightsCheckedListBox.Items.AddRange(@(
	"AppendData",
	"ChangePermissions",
	"CreateDirectories",
	"CreateFiles",
	"Delete",
	"DeleteSubdirectoriesAndFiles",
	"ExecuteFile",
	"FullControl",
	"ListDirectory",
	"Modify",
	"Read",
	"ReadAndExecute",
	"ReadAttributes",
	"ReadData",
	"ReadExtendedAttributes",
	"ReadPermissions",
	"Synchronize",
	"TakeOwnership",
	"Traverse",
	"Write",
	"WriteAttributes",
	"WriteData",
	"WriteExtendedAttributes"))
	$rightsCheckedListBox.Location = New-Object System.Drawing.Point(7, 20)
	$rightsCheckedListBox.Name = "rightsCheckedListBox"
	$rightsCheckedListBox.Size = New-Object System.Drawing.Size(187, 229)
	$rightsCheckedListBox.TabIndex = 12
	#
	# fileGroupBox
	#
	$fileGroupBox.Controls.Add($openTemplateButton)
	$fileGroupBox.Controls.Add($pathTextBox)
	$fileGroupBox.Controls.Add($pathLabel)
	$fileGroupBox.Controls.Add($multipleRadioButton)
	$fileGroupBox.Controls.Add($singleRadioButton)
	$fileGroupBox.Location = New-Object System.Drawing.Point(12, 13)
	$fileGroupBox.Name = "fileGroupBox"
	$fileGroupBox.Size = New-Object System.Drawing.Size(460, 70)
	$fileGroupBox.TabIndex = 0
	$fileGroupBox.TabStop = $false
	$fileGroupBox.Text = "File"
	#
	# multipleRadioButton
	#
	$multipleRadioButton.AutoSize = $true
	$multipleRadioButton.Location = New-Object System.Drawing.Point(6, 43)
	$multipleRadioButton.Name = "multipleRadioButton"
	$multipleRadioButton.Size = New-Object System.Drawing.Size(61, 17)
	$multipleRadioButton.TabIndex = 2
	$multipleRadioButton.Text = "Multiple"
	$multipleRadioButton.UseVisualStyleBackColor = $true
	$multipleRadioButton.Add_CheckedChanged({ToggleSingleMultiple})
	#
	# singleRadioButton
	#
	$singleRadioButton.AutoSize = $true
	$singleRadioButton.Checked = $true
	$singleRadioButton.Location = New-Object System.Drawing.Point(6, 19)
	$singleRadioButton.Name = "singleRadioButton"
	$singleRadioButton.Size = New-Object System.Drawing.Size(54, 17)
	$singleRadioButton.TabIndex = 1
	$singleRadioButton.TabStop = $true
	$singleRadioButton.Text = "Single"
	$singleRadioButton.UseVisualStyleBackColor = $true
	$singleRadioButton.Add_CheckedChanged({ToggleSingleMultiple})
	#
	# pathLabel
	#
	$pathLabel.AutoSize = $true
	$pathLabel.Location = New-Object System.Drawing.Point(70, 21)
	$pathLabel.Name = "pathLabel"
	$pathLabel.Size = New-Object System.Drawing.Size(32, 13)
	$pathLabel.TabIndex = 3
	$pathLabel.Text = "Path:"
	#
	# pathTextBox
	#
	$pathTextBox.Location = New-Object System.Drawing.Point(108, 17)
	$pathTextBox.Name = "pathTextBox"
	$pathTextBox.Size = New-Object System.Drawing.Size(346, 20)
	$pathTextBox.TabIndex = 4
	#
	# openTemplateButton
	#
	$openTemplateButton.Enabled = $false
	$openTemplateButton.Location = New-Object System.Drawing.Point(73, 43)
	$openTemplateButton.Name = "openTemplateButton"
	$openTemplateButton.Size = New-Object System.Drawing.Size(381, 23)
	$openTemplateButton.TabIndex = 5
	$openTemplateButton.Text = "OpenTemplate"
	$openTemplateButton.UseVisualStyleBackColor = $true
	$openTemplateButton.Add_Click({OnOpenTemplateButtonClick})
	#
	# inheritanceGroupBox
	#
	$inheritanceGroupBox.Controls.Add($inheritanceCheckedListBox)
	$inheritanceGroupBox.Location = New-Object System.Drawing.Point(218, 165)
	$inheritanceGroupBox.Name = "inheritanceGroupBox"
	$inheritanceGroupBox.Size = New-Object System.Drawing.Size(254, 90)
	$inheritanceGroupBox.TabIndex = 14
	$inheritanceGroupBox.TabStop = $false
	$inheritanceGroupBox.Text = "Inheritance"
	#
	# inheritanceCheckedListBox
	#
	$inheritanceCheckedListBox.CheckOnClick = $true
	$inheritanceCheckedListBox.FormattingEnabled = $true
	$inheritanceCheckedListBox.Items.AddRange(@(
	"ContainerInherit",
	"None",
	"ObjectInherit"))
	$inheritanceCheckedListBox.Location = New-Object System.Drawing.Point(6, 19)
	$inheritanceCheckedListBox.Name = "inheritanceCheckedListBox"
	$inheritanceCheckedListBox.Size = New-Object System.Drawing.Size(242, 64)
	$inheritanceCheckedListBox.TabIndex = 15
	$inheritanceCheckedListBox.SetItemChecked(0, $true)
	$inheritanceCheckedListBox.SetItemChecked(2, $true)
	#
	# propagationGroupBox
	#
	$propagationGroupBox.Controls.Add($propagationCheckedListBox)
	$propagationGroupBox.Location = New-Object System.Drawing.Point(218, 261)
	$propagationGroupBox.Name = "propagationGroupBox"
	$propagationGroupBox.Size = New-Object System.Drawing.Size(254, 90)
	$propagationGroupBox.TabIndex = 16
	$propagationGroupBox.TabStop = $false
	$propagationGroupBox.Text = "Propagation"
	#
	# propagationCheckedListBox
	#
	$propagationCheckedListBox.CheckOnClick = $true
	$propagationCheckedListBox.FormattingEnabled = $true
	$propagationCheckedListBox.Items.AddRange(@(
	"InheritOnly",
	"None",
	"NoPropagateInherit"))
	$propagationCheckedListBox.Location = New-Object System.Drawing.Point(6, 19)
	$propagationCheckedListBox.Name = "propagationCheckedListBox"
	$propagationCheckedListBox.Size = New-Object System.Drawing.Size(242, 64)
	$propagationCheckedListBox.TabIndex = 17
	$propagationCheckedListBox.SetItemChecked(1, $true)
	#
	# actGroupBox
	#
	$actGroupBox.Controls.Add($actDenyRadioButton)
	$actGroupBox.Controls.Add($actAllowRadioButton)
	$actGroupBox.Location = New-Object System.Drawing.Point(218, 357)
	$actGroupBox.Name = "actGroupBox"
	$actGroupBox.Size = New-Object System.Drawing.Size(254, 70)
	$actGroupBox.TabIndex = 18
	$actGroupBox.TabStop = $false
	$actGroupBox.Text = "AccessControlType"
	#
	# actAllowRadioButton
	#
	$actAllowRadioButton.AutoSize = $true
	$actAllowRadioButton.Checked = $true
	$actAllowRadioButton.Location = New-Object System.Drawing.Point(7, 20)
	$actAllowRadioButton.Name = "actAllowRadioButton"
	$actAllowRadioButton.Size = New-Object System.Drawing.Size(50, 17)
	$actAllowRadioButton.TabIndex = 19
	$actAllowRadioButton.TabStop = $true
	$actAllowRadioButton.Text = "Allow"
	$actAllowRadioButton.UseVisualStyleBackColor = $true
	#
	# actDenyRadioButton
	#
	$actDenyRadioButton.AutoSize = $true
	$actDenyRadioButton.Location = New-Object System.Drawing.Point(7, 44)
	$actDenyRadioButton.Name = "actDenyRadioButton"
	$actDenyRadioButton.Size = New-Object System.Drawing.Size(50, 17)
	$actDenyRadioButton.TabIndex = 20
	$actDenyRadioButton.Text = "Deny"
	$actDenyRadioButton.UseVisualStyleBackColor = $true
	#
	# userGroupComboBox
	#
	$userGroupComboBox.AutoCompleteCustomSource.AddRange($fullList)
	$userGroupComboBox.AutoCompleteMode = [System.Windows.Forms.AutoCompleteMode]::SuggestAppend
	$userGroupComboBox.AutoCompleteSource = [System.Windows.Forms.AutoCompleteSource]::CustomSource
	$userGroupComboBox.FormattingEnabled = $true
	$userGroupComboBox.Items.AddRange($fullList)
	$userGroupComboBox.Location = New-Object System.Drawing.Point(79, 44)
	$userGroupComboBox.MaxDropDownItems = 16
	$userGroupComboBox.Name = "userGroupComboBox"
	$userGroupComboBox.Size = New-Object System.Drawing.Size(375, 21)
	$userGroupComboBox.TabIndex = 10
	#
	# continuousProgressBar
	#
	$continuousProgressBar.Location = New-Object System.Drawing.Point(218, 433)
	$continuousProgressBar.Name = "continuousProgressBar"
	$continuousProgressBar.Size = New-Object System.Drawing.Size(254, 17)
	$continuousProgressBar.TabIndex = 21
	$continuousProgressBar.Style = "Continuous"
	#
	# setPermissionsButton
	#
	$setPermissionsButton.Location = New-Object System.Drawing.Point(12, 456)
	$setPermissionsButton.Name = "setPermissionsButton"
	$setPermissionsButton.Size = New-Object System.Drawing.Size(460, 23)
	$setPermissionsButton.TabIndex = 22
	$setPermissionsButton.Text = "Add Permissions"
	$setPermissionsButton.UseVisualStyleBackColor = $true
	$setPermissionsButton.Add_Click({OnSetPermissionsButtonClick})
	#
	# setPermissionsForm
	#
	$setPermissionsForm.ClientSize = New-Object System.Drawing.Size(484, 491)
	$setPermissionsForm.Controls.Add($setPermissionsButton)
	$setPermissionsForm.Controls.Add($continuousProgressBar)
	$setPermissionsForm.Controls.Add($actGroupBox)
	$setPermissionsForm.Controls.Add($propagationGroupBox)
	$setPermissionsForm.Controls.Add($inheritanceGroupBox)
	$setPermissionsForm.Controls.Add($fileGroupBox)
	$setPermissionsForm.Controls.Add($rightsGroupBox)
	$setPermissionsForm.Controls.Add($identityGroupBox)
	$setPermissionsForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$setPermissionsForm.MaximizeBox = $false
	$setPermissionsForm.MinimizeBox = $false
	$setPermissionsForm.Name = "setPermissionsForm"
	$setPermissionsForm.Text = "Set-ACLPermissions"
	$setPermissionsForm.Add_Shown({$setPermissionsForm.Activate()})
	
	Write-Host "Loaded setPermissionsForm."
	$progressBar1.Value = 0
	CheckForErrors
	
	$setPermissionsForm.ShowDialog()
	$setPermissionsForm.Dispose()

	Stop-Transcript
}
function Set-EmailForwarding {
	Set-Mailbox -Identity "Douglas Kohn" -DeliverToMailboxAndForward $true -ForwardingSMTPAddress "douglaskohn.parents@fineartschool.net"
	Set-Mailbox -Identity "Ken Sanchez" -ForwardingAddress "pilarp@contoso.com"
}
function Set-NTP {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Set-NTP.txt"
	Write-Host "Running Set-NTP script..."
	$progressBar1.Value = 10
	function OnSetSourceButtonClick {
		Write-Host "setSourceButton clicked."
		$progressBar1.Value = 10
		w32tm /config /syncfromflags:manual /manualpeerlist:time.windows.com,0x8 /reliable:yes /update
		# With IP address:
		# w32tm /config /syncfromflags:manual /manualpeerlist:168.61.215.74,0x8 /reliable:yes /update
		$progressBar1.Value = 50
		w32tm /config /update
		$progressBar1.Value = 80
		CheckForErrors
		OperationComplete
	}
	function OnCheckConfigButtonClick {
		Write-Host "checkConfigButton clicked."
		$progressBar1.Value = 10
		$outputTextBox.Text = w32tm /query /configuration
		$progressBar1.Value = 50
		CheckForErrors
		OperationComplete
	}
	function OnCheckSourceButtonClick {
		Write-Host "checkSourceButton clicked."
		$progressBar1.Value = 10
		$outputTextBox.Text = w32tm /query /source
		$progressBar1.Value = 50
		CheckForErrors
		OperationComplete
	}
	function OnForceResyncButtonClick {
		$progressBar1.Value = 10
		$outputTextBox.Text = w32tm /resync /force
		$progressBar1.Value = 50
		CheckForErrors
		OperationComplete
	}

	$scriptForm12 = New-Object System.Windows.Forms.Form

	$setSourceButton = New-Object System.Windows.Forms.Button
	$checkConfigButton = New-Object System.Windows.Forms.Button
	$checkSourceButton = New-Object System.Windows.Forms.Button
	$forceResyncButton = New-Object System.Windows.Forms.Button
	$outputTextBox = New-Object System.Windows.Forms.TextBox
	#
	# setSourceButton
	#
	$setSourceButton.Location = New-Object System.Drawing.Point(12, 12)
	$setSourceButton.Name = "setSourceButton"
	$setSourceButton.Size = New-Object System.Drawing.Size(260, 23)
	$setSourceButton.TabIndex = 1
	$setSourceButton.Text = "Set time source to time.windows.com"
	$setSourceButton.UseVisualStyleBackColor = $true
	$setSourceButton.Add_Click({OnSetSourceButtonClick})
	#
	# checkConfigButton
	#
	$checkConfigButton.Location = New-Object System.Drawing.Point(12, 41)
	$checkConfigButton.Name = "checkConfigButton"
	$checkConfigButton.Size = New-Object System.Drawing.Size(260, 23)
	$checkConfigButton.TabIndex = 2
	$checkConfigButton.Text = "Check current configuration"
	$checkConfigButton.UseVisualStyleBackColor = $true
	$checkConfigButton.Add_Click({OnCheckConfigButtonClick})
	#
	# checkSourceButton
	#
	$checkSourceButton.Location = New-Object System.Drawing.Point(12, 70)
	$checkSourceButton.Name = "checkSourceButton"
	$checkSourceButton.Size = New-Object System.Drawing.Size(260, 23)
	$checkSourceButton.TabIndex = 4
	$checkSourceButton.Text = "Check current time source"
	$checkSourceButton.UseVisualStyleBackColor = $true
	$checkSourceButton.Add_Click({OnCheckSourceButtonClick})
	#
	# forceResyncButton
	#
	$forceResyncButton.Location = New-Object System.Drawing.Point(12, 99)
	$forceResyncButton.Name = "forceResyncButton"
	$forceResyncButton.Size = New-Object System.Drawing.Size(260, 23)
	$forceResyncButton.TabIndex = 5
	$forceResyncButton.Text = "Force resync with time source"
	$forceResyncButton.UseVisualStyleBackColor = $true
	$forceResyncButton.Add_Click({OnForceResyncButtonClick})
	#
	# outputTextBox
	#
	$outputTextBox.Location = New-Object System.Drawing.Point(13, 128)
	$outputTextBox.Multiline = $true
	$outputTextBox.Name = "outputTextBox"
	$outputTextBox.ReadOnly = $true
	$outputTextBox.Size = New-Object System.Drawing.Size(259, 171)
	$outputTextBox.TabIndex = 6
	#
	# scriptForm12
	#
	$scriptForm12.ClientSize = New-Object System.Drawing.Size(284, 311)
	$scriptForm12.Controls.Add($outputTextBox)
	$scriptForm12.Controls.Add($forceResyncButton)
	$scriptForm12.Controls.Add($checkSourceButton)
	$scriptForm12.Controls.Add($checkConfigButton)
	$scriptForm12.Controls.Add($setSourceButton)
	$scriptForm12.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$scriptForm12.MaximizeBox = $false
	$scriptForm12.MinimizeBox = $false
	$scriptForm12.Name = "scriptForm12"
	$scriptForm12.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$scriptForm12.Text = "Set-NTP"
	$scriptForm12.Add_Shown({$scriptForm12.Activate()})

	Write-Host "Loaded ScriptForm12."
	$progressBar1.Value = 0
	CheckForErrors

	$scriptForm12.ShowDialog()
	$scriptForm12.Dispose()

	Stop-Transcript
}
function Show-Information {
	Start-Transcript -IncludeInvocationHeader -Path ".\Logs\Show-Information.txt"
	Write-Host "Running Show-Information script..."
	$progressBar1.Value = 10
	function OnOpenRepoButtonClick {
		Start-Process "https://github.com/DiadNetworks/Script-Package"
	}
	function OnOpenIssueButtonClick {
		Start-Process "https://github.com/DiadNetworks/Script-Package/issues"
	}
	function OnViewReleasesButtonClick {
		Start-Process "https://github.com/DiadNetworks/Script-Package/releases"
	}
	function  OnDownloadPortableButtonClick {
		Start-Process "https://github.com/DiadNetworks/Script-Package/releases/latest/download/Script-Package.zip"
	}
	function OnViewReadmeButtonClick {
		Start-Process "https://github.com/DiadNetworks/Script-Package/blob/main/README.md"
	}
	
	$infoForm = New-Object System.Windows.Forms.Form
	
	$logoBox = New-Object System.Windows.Forms.PictureBox
	$openRepoButton = New-Object System.Windows.Forms.Button
	$openIssueButton = New-Object System.Windows.Forms.Button
	$viewReleasesButton = New-Object System.Windows.Forms.Button
	$downloadPortableButton = New-Object System.Windows.Forms.Button
	$viewReadmeButton = New-Object System.Windows.Forms.Button
	#
	# logoBox
	#
	$logoBox.BorderStyle = [System.Windows.Forms.BorderStyle]::None
	$logoBox.Image = [System.Drawing.Image]::FromFile(".\Images\logo.png")
	$logoBox.Location = New-Object System.Drawing.Point(12, 12)
	$logoBox.Name = "logoBox"
	$logoBox.Size = New-Object System.Drawing.Size(50, 50)
	$logoBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
	$logoBox.TabIndex = 0
	$logoBox.TabStop = $false
	#
	# openRepoButton
	#
	$openRepoButton.Cursor = [System.Windows.Forms.Cursors]::Hand
	$openRepoButton.Location = New-Object System.Drawing.Point(68, 12)
	$openRepoButton.Name = "openRepoButton"
	$openRepoButton.Size = New-Object System.Drawing.Size(304, 50)
	$openRepoButton.TabIndex = 1
	$openRepoButton.Text = "Open GitHub Repository"
	$openRepoButton.Add_Click({ OnOpenRepoButtonClick })
	$openRepoButton.UseVisualStyleBackColor = $true
	#
	# openIssueButton
	#
	$openIssueButton.Cursor = [System.Windows.Forms.Cursors]::Hand
	$openIssueButton.Location = New-Object System.Drawing.Point(12, 68)
	$openIssueButton.Name = "openIssueButton"
	$openIssueButton.Size = New-Object System.Drawing.Size(360, 50)
	$openIssueButton.TabIndex = 2
	$openIssueButton.Text = "Report an Issue or Make a Suggestion"
	$openIssueButton.Add_Click({ OnOpenIssueButtonClick })
	$openIssueButton.UseVisualStyleBackColor = $true
	#
	# viewReleasesButton
	#
	$viewReleasesButton.Cursor = [System.Windows.Forms.Cursors]::Hand
	$viewReleasesButton.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 8.25,[System.Drawing.FontStyle]::Underline,[System.Drawing.GraphicsUnit]::Point, 0)
	$viewReleasesButton.Location = New-Object System.Drawing.Point(12, 124)
	$viewReleasesButton.Name = "viewReleasesButton"
	$viewReleasesButton.Size = New-Object System.Drawing.Size(360, 50)
	$viewReleasesButton.TabIndex = 3
	$viewReleasesButton.Text = "View All Releases"
	$viewReleasesButton.Add_Click({ OnViewReleasesButtonClick })
	$viewReleasesButton.UseVisualStyleBackColor = $true
	#
	# downloadPortableButton
	#
	$downloadPortableButton.Cursor = [System.Windows.Forms.Cursors]::Hand
	$downloadPortableButton.Location = New-Object System.Drawing.Point(12, 180)
	$downloadPortableButton.Name = "downloadPortableButton"
	$downloadPortableButton.Size = New-Object System.Drawing.Size(360, 50)
	$downloadPortableButton.TabIndex = 4
	$downloadPortableButton.Text = "Download Portable Version"
	$downloadPortableButton.Add_Click({ OnDownloadPortableButtonClick })
	$downloadPortableButton.UseVisualStyleBackColor = $true
	#
	# viewReadmeButton
	#
	$viewReadmeButton.Cursor = [System.Windows.Forms.Cursors]::Hand
	$viewReadmeButton.Location = New-Object System.Drawing.Point(12, 236)
	$viewReadmeButton.Name = "viewReadmeButton"
	$viewReadmeButton.Size = New-Object System.Drawing.Size(360, 50)
	$viewReadmeButton.TabIndex = 5
	$viewReadmeButton.Text = "View README"
	$viewReadmeButton.Add_Click({ OnViewReadmeButtonClick })
	$viewReadmeButton.UseVisualStyleBackColor = $true
	#
	# infoForm
	#
	$infoForm.ClientSize = New-Object System.Drawing.Size(384, 298)
	$infoForm.Controls.Add($viewReadmeButton)
	$infoForm.Controls.Add($downloadPortableButton)
	$infoForm.Controls.Add($viewReleasesButton)
	$infoForm.Controls.Add($openIssueButton)
	$infoForm.Controls.Add($openRepoButton)
	$infoForm.Controls.Add($logoBox)
	$infoForm.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 8.25,[System.Drawing.FontStyle]::Underline,[System.Drawing.GraphicsUnit]::Point, 0)
	$infoForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Fixed3D
	$infoForm.Icon = ".\Images\logo.ico"
	$infoForm.MaximizeBox = $false
	$infoForm.MinimizeBox = $false
	$infoForm.Name = "infoForm"
	$infoForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$infoForm.Text = "Information"
	$infoForm.Add_Shown({$infoForm.Activate()})
	
	Write-Host "Loaded infoForm."
	$progressBar1.Value = 0

	$infoForm.ShowDialog()
	$infoForm.Dispose()

	Stop-Transcript
}

# This list is what will be visible in the scriptSelect ComboBox
$scriptList = @(
	"Add-AuthenticationPhoneMethod",
	"Add-AutoReply",
	"Add-Contacts",
	"Add-DistributionListMember",
	"Add-EmailAlias",
	"Add-MailboxMember",
	"Add-TrustedSender",
	"Add-UnifiedGroupMember",
	"Block-User",
	"Clear-RecycleBin",
	"Convert-UnifiedGroupToDistributionGroup",
	"Enable-Archive",
	"Install-RequiredModules",
	"New-ADAccounts",
	"New-ADAndEmailAccounts",
	"New-EmailAccounts",
	"Remove-DistributionListMember",
	"Remove-EmailAlias",
	"Remove-MailboxMember",
	"Remove-UnifiedGroupMember",
	"Update-ScriptPackage",
	"Set-ACLPermissions",
	"Set-NTP",
	"Show-Information"
)

# Main GUI functions

# Return the directory name of this script
function Get-ScriptDirectory {
	Get-Location | Select-Object -ExpandProperty Path
}
# Return the number of physical cores in the system
function Get-SystemCoreCount {
	Get-CimInstance -ClassName Win32_Processor | Select-Object -ExpandProperty NumberOfCores
}
function OnRunButtonClick {
    # Get the selected script from the ComboBox
	# selectedScriptDropdownOnly doesn't work if a value is typed, only if selected from the dropdown
    # $selectedScriptDropdownOnly = $scriptSelect.SelectedItem.ToString()
	$selectedScript = $scriptSelect.Text

    # Perform actions based on the selected script
    switch ($selectedScript) {
		"Add-AuthenticationPhoneMethod" { Add-AuthenticationPhoneMethod }
		"Add-AutoReply" { Add-AutoReply }
		"Add-Contacts" { Add-Contacts }
		"Add-DistributionListMember" { Add-DistributionListMember }
		"Add-EmailAlias" { Add-EmailAlias }
        "Add-MailboxMember" { Add-MailboxMember }
		"Add-TrustedSender" { Add-TrustedSender }
		"Add-UnifiedGroupMember" { Add-UnifiedGroupMember }
        "Block-User" { Block-User }
		"Clear-RecycleBin" { Clear-RecycleBin }
		"Convert-UnifiedGroupToDistributionGroup" { Convert-UnifiedGroupToDistributionGroup }
		"Enable-Archive" { Enable-Archive }
		"Install-RequiredModules" { Install-RequiredModules }
		"New-ADAccounts" { New-ADAccounts }
        "New-ADAndEmailAccounts" { New-ADAndEmailAccounts }
		"New-EmailAccounts" { New-EmailAccounts }
		"Remove-DistributionListMember" { Remove-DistributionListMember }
		"Remove-EmailAlias" { Remove-EmailAlias }
		"Remove-MailboxMember" { Add-MailboxMember }
		"Remove-UnifiedGroupMember" { Remove-UnifiedGroupMember }
		"Update-ScriptPackage" { Update-ScriptPackage }
		"Set-ACLPermissions" { Set-ACLPermissions }
		"Set-NTP" { Set-NTP }
		"Show-Information" { Show-Information }
		"Debug" { Start-Process pwsh .\MainGUI.ps1 }
		"Reload-Settings" { LoadSettings }
        default { Write-Host "No script selected." }
    }
}
function OnSignInButtonClick {
	Write-Host "SignInButton clicked."
	$progressBar1.Value = 10

	Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All"
	Write-Host "Connected to Graph"
	$progressBar1.Value = 50
	CheckForErrors

	Connect-ExchangeOnline -ShowBanner:$false -SkipLoadingCmdletHelp #-SkipLoadingFormatData
	Write-Host "Connected to Exchange"
	$progressBar1.Value = 100
	CheckForErrors

	$currentMgContext = Get-MgContext
	$label1.Text = "Currently signed in as:`n" + $currentMgContext.Account
	$progressBar1.Value = 0
	CheckForErrors
}
function OnSignOutButtonClick {
	Write-Host "SignOutButton clicked."
	$progressBar1.Value = 10

	Disconnect-Graph
	Write-Host "Disconnected from Graph"
	$progressBar1.Value = 50
	CheckForErrors

	Disconnect-ExchangeOnline -Confirm:$false
	Write-Host "Disconnected from Exchange"
	$progressBar1.Value = 100
	CheckForErrors

	$label1.Text = "Currently not signed in."
	$progressBar1.Value = 0
}
#
# Main GUI
#
# Loading external assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
# Enable visual styles, will be commented out if settings.ini is enabled
[System.Windows.Forms.Application]::EnableVisualStyles()

$MainWindow = New-Object System.Windows.Forms.Form

$scriptSelect = New-Object System.Windows.Forms.ComboBox
$runButton = New-Object System.Windows.Forms.Button
$progressBar1 = New-Object System.Windows.Forms.ProgressBar
$signInButton = New-Object System.Windows.Forms.Button
$label1 = New-Object System.Windows.Forms.Label
$signOutButton = New-Object System.Windows.Forms.Button
#
# scriptSelect
#
$scriptSelect.AutoCompleteCustomSource.AddRange($scriptList)
$scriptSelect.AutoCompleteMode = [System.Windows.Forms.AutoCompleteMode]::SuggestAppend
$scriptSelect.AutoCompleteSource = [System.Windows.Forms.AutoCompleteSource]::CustomSource
$scriptSelect.FormattingEnabled = $true
$scriptSelect.Items.AddRange($scriptList)
$scriptSelect.Location = New-Object System.Drawing.Point(12, 70)
$scriptSelect.Name = "scriptSelect"
$scriptSelect.Size = New-Object System.Drawing.Size(356, 21)
$scriptSelect.TabIndex = 0
$scriptSelect.Text = "Select or enter a script"
$scriptSelect.MaxDropDownItems = 16
#
# runButton
#
$runButton.Location = New-Object System.Drawing.Point(293, 97)
$runButton.Name = "runButton"
$runButton.Size = New-Object System.Drawing.Size(75, 23)
$runButton.TabIndex = 1
$runButton.Text = "Run"
$runButton.UseVisualStyleBackColor = $true
$runButton.Add_Click({ OnRunButtonClick })
#
# progressBar1
#
$progressBar1.Location = New-Object System.Drawing.Point(12, 97)
$progressBar1.Name = "progressBar1"
$progressBar1.Size = New-Object System.Drawing.Size(275, 23)
$progressBar1.TabIndex = 2
$progressBar1.Style = "Continuous"
#
# signInButton
#
$signInButton.Location = New-Object System.Drawing.Point(292, 13)
$signInButton.Name = "signInButton"
$signInButton.Size = New-Object System.Drawing.Size(75, 23)
$signInButton.TabIndex = 3
$signInButton.Text = "Sign In"
$signInButton.UseVisualStyleBackColor = $true
$signInButton.Add_Click({ OnSignInButtonClick })
#
# label1
#
$label1.AutoSize = $true
$label1.Location = New-Object System.Drawing.Point(13, 13)
$label1.Name = "label1"
$label1.Size = New-Object System.Drawing.Size(113, 13)
$label1.TabIndex = 4
$label1.Text = "Currently not signed in."
#
# signOutButton
#
$signOutButton.Location = New-Object System.Drawing.Point(292, 42)
$signOutButton.Name = "signOutButton"
$signOutButton.Size = New-Object System.Drawing.Size(75, 23)
$signOutButton.TabIndex = 5
$signOutButton.Text = "Sign Out"
$signOutButton.UseVisualStyleBackColor = $true
$signOutButton.Add_Click({ OnSignOutButtonClick })
#
# MainWindow
#
$MainWindow.AcceptButton = $runButton
$MainWindow.ClientSize = New-Object System.Drawing.Size(380, 132)
$MainWindow.Controls.Add($signOutButton)
$MainWindow.Controls.Add($label1)
$MainWindow.Controls.Add($signInButton)
$MainWindow.Controls.Add($progressBar1)
$MainWindow.Controls.Add($runButton)
$MainWindow.Controls.Add($scriptSelect)
$MainWindow.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Fixed3D
$MainWindow.MaximizeBox = $false
$MainWindow.MinimizeBox = $true
$MainWindow.Name = "MainWindow"
$MainWindow.Text = "Script-Package $version"
$MainWindow.Icon = ".\Images\logo.ico"
$MainWindow.StartPosition = "WindowsDefaultLocation"

# When Main GUI closed
function OnFormClosing_MainWindow{ 
	Disconnect-ExchangeOnline -Confirm:$false
	Disconnect-Graph

	#Sets the value indicating that the event should be canceled.
	($_).Cancel= $False
}
$MainWindow.Add_FormClosing({OnFormClosing_MainWindow})
$MainWindow.Add_Shown({$MainWindow.Activate()})
#
# ErrorForm
#
$ErrorForm = New-Object System.Windows.Forms.Form

$errorBox = New-Object System.Windows.Forms.TextBox
#
# errorBox
#
$errorBox.Anchor = [System.Windows.Forms.AnchorStyles]"Top,Bottom,Left,Right"
$errorBox.Cursor = [System.Windows.Forms.Cursors]::IBeam
$errorBox.Location = New-Object System.Drawing.Point(12, 12)
$errorBox.Multiline = $true
$errorBox.Name = "errorBox"
$errorBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
$errorBox.Size = New-Object System.Drawing.Size(360, 337)
$errorBox.TabIndex = 0
$errorBox.ReadOnly = $true
#
# ErrorForm
#
$ErrorForm.ClientSize = New-Object System.Drawing.Size(384, 361)
$ErrorForm.Controls.Add($errorBox)
$ErrorForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::SizableToolWindow
$ErrorForm.MinimizeBox = $false
$ErrorForm.Name = "ErrorForm"
$ErrorForm.Text = "Errors"

# When Error form closed
function OnFormClosing_ErrorForm{ 
	# $this parameter is equal to the sender (object)
	# $_ is equal to the parameter e (eventarg)

	# The CloseReason property indicates a reason for the closure :
	#   if (($_).CloseReason -eq [System.Windows.Forms.CloseReason]::UserClosing)

	#Sets the value indicating that the event should be canceled.
	($_).Cancel= $False
}
$ErrorForm.Add_FormClosing( { OnFormClosing_ErrorForm} )
$ErrorForm.Add_Shown({$ErrorForm.Activate()})

# Function to heck for errors and show error form if there are any
function CheckForErrors {
	if ($Error) {
		$errorBox.Text = $Error
		$ErrorForm.ShowDialog()
		$Error.Clear()
	}
}
#
# Operation Complete form
#
$operationCompleteForm = New-Object System.Windows.Forms.Form

$closeFormButton = New-Object System.Windows.Forms.Button
#
# closeFormButton
#
$closeFormButton.Location = New-Object System.Drawing.Point(105, 44)
$closeFormButton.Name = "closeFormButton"
$closeFormButton.Size = New-Object System.Drawing.Size(75, 23)
$closeFormButton.TabIndex = 0
$closeFormButton.Text = "OK!"
$closeFormButton.UseVisualStyleBackColor = $true
$closeFormButton.Add_Click({
	$progressBar1.Value = 0
	$operationCompleteForm.Close()
	Write-Host "Closed OperationComplete form."
})
#
# operationCompleteForm
#
$operationCompleteForm.AcceptButton = $closeFormButton
$operationCompleteForm.ClientSize = New-Object System.Drawing.Size(284, 111)
$operationCompleteForm.Controls.Add($closeFormButton)
$operationCompleteForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
$operationCompleteForm.MaximizeBox = $false
$operationCompleteForm.MinimizeBox = $false
$operationCompleteForm.Name = "operationCompleteForm"
$operationCompleteForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
$operationCompleteForm.Text = "Operation Complete"
$operationCompleteForm.Add_Shown({$operationCompleteForm.Activate()})

# Function to show operation complete form
function OperationComplete {
	$progressBar1.Value = 100
	Write-Host "Operation complete."
	$operationCompleteForm.ShowDialog()
}
# Function to show warning form
function ShowWarningForm {
	param (
		[Parameter(Mandatory=$true)]
		[string]$warningText
	)
	Write-Host "Showing warning form..."
	$userClickedConfirm = New-Object PSObject -Property @{ Value = $false }
	Write-Host "userClickedConfirm is $($userClickedConfirm.Value)"
	#
	# Warning form
	#
	$warningForm = New-Object System.Windows.Forms.Form

	$confirmWarningButton = New-Object System.Windows.Forms.Button
	$confirmWarningCheckBox = New-Object System.Windows.Forms.CheckBox
	$warningTextLabel = New-Object System.Windows.Forms.Label
	#
	# confirmWarningButton
	#
	$confirmWarningButton.Enabled = $false
	$confirmWarningButton.Location = New-Object System.Drawing.Point(12, 126)
	$confirmWarningButton.Name = "confirmWarningButton"
	$confirmWarningButton.Size = New-Object System.Drawing.Size(360, 23)
	$confirmWarningButton.TabIndex = 2
	$confirmWarningButton.Text = "Confirm"
	$confirmWarningButton.UseVisualStyleBackColor = $true
	$confirmWarningButton.Add_Click({
		Write-Host "User clicked confirm."
		$userClickedConfirm.Value = $true
		Write-Host "userClickedConfirm is $($userClickedConfirm.Value)"
		$warningForm.Close()
	})
	#
	# confirmWarningCheckBox
	#
	$confirmWarningCheckBox.AutoSize = $true
	$confirmWarningCheckBox.Location = New-Object System.Drawing.Point(12, 103)
	$confirmWarningCheckBox.Name = "confirmWarningCheckBox"
	$confirmWarningCheckBox.Size = New-Object System.Drawing.Size(129, 17)
	$confirmWarningCheckBox.TabIndex = 1
	$confirmWarningCheckBox.Text = "I know what I'm doing"
	$confirmWarningCheckBox.UseVisualStyleBackColor = $true
	$confirmWarningCheckBox.Add_CheckedChanged({
		if ($confirmWarningCheckBox.Checked) {
			Write-Host "confirmWarningCheckBox is checked."
			$confirmWarningButton.Enabled = $true
		} else {
			Write-Host "confirmWarningCheckBox is unchecked."
			$confirmWarningButton.Enabled = $false
		}
	})
	#
	# warningTextLabel
	#
	$warningTextLabel.AutoSize = $true
	$warningTextLabel.Location = New-Object System.Drawing.Point(12, 9)
	$warningTextLabel.MaximumSize = New-Object System.Drawing.Size(360, 0)
	$warningTextLabel.Name = "warningTextLabel"
	$warningTextLabel.Size = New-Object System.Drawing.Size(71, 13)
	$warningTextLabel.TabIndex = 0
	$warningTextLabel.Text = "Warning!"
	$warningTextLabel.Text = $warningText
	#
	# warningForm
	#
	$warningForm.ClientSize = New-Object System.Drawing.Size(384, 161)
	$warningForm.Controls.Add($warningTextLabel)
	$warningForm.Controls.Add($confirmWarningCheckBox)
	$warningForm.Controls.Add($confirmWarningButton)
	$warningForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$warningForm.MaximizeBox = $false
	$warningForm.MinimizeBox = $false
	$warningForm.Name = "warningForm"
	$warningForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
	$warningForm.Text = "Warning!"
	$warningForm.Add_Shown({$warningForm.Activate()})
	$warningForm.Add_FormClosing({
		$confirmWarningCheckBox.Checked = $false
	})
	$warningForm.ShowDialog()
	Write-Host "Returning result... $($userClickedConfirm.Value)"
	return $userClickedConfirm.Value
}

# Load settings from settings.ini - currently disabled
#LoadSettings

Write-Host "Loaded MainGUI."
CheckForErrors
# Show MainWindow
$MainWindow.ShowDialog()

# Release the forms
$MainWindow.Dispose()
$ErrorForm.Dispose()
$operationCompleteForm.Dispose()
$warningForm.Dispose()