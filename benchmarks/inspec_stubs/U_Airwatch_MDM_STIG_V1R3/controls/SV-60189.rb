control 'SV-60189' do
  title 'The AirWatch MDM Server must be capable of scanning the hardware version of managed mobile devices and alert if unsupported versions are found.'
  desc 'Approved versions of devices have gone though all required phases of testing, approval, etc., and are able to support required security features.  Using non-approved versions of mobile device hardware could compromise the security baseline of the mobile system, since some required security features may not be supported.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server is able to be configured to scan the version of the mobile device hardware and alert if unsupported versions are found. If the AirWatch MDM Server cannot be configured to scan the hardware version of managed mobile devices and alert if unsupported versions are found, this is a finding.

To verify Hardware Version compliance policy is set to notify Administrators of infractions: (1) click "Menu" on top tool bar, (2) click "Compliance" under "Profiles and Policies" heading, (3) click on applicable compliance policy, and (4) validate that "Model" is listed in first drop-down menu, (5) "Is" or "Is Not" as applicable is listed in second drop-down menu, and (6) proper Hardware Version to specify is listed in third drop-down menu. (7) Click "Next". (8) Ensure "Notify" is listed in first drop-down menu, (9) that "Send Email to Administrator" is listed in second drop-down menu, and (10) email(s) of applicable administrators is (are) entered in box labeled "To:". (11) Click "Next". (12) Ensure appropriate information for Assignment of policy to particular platforms, groups, and/or users.'
  desc 'fix', 'Use only AirWatch MDM Servers that are capable of scanning the hardware version of managed mobile devices and alert if unsupported versions are found.

To define Hardware Version compliance policy to notify Administrators of infractions:  (1) click "Add" from the console top toolbar, and (2) click "Compliance Policy" from the drop-down menu. From the Compliance Policy window, (3) choose "Model" in first drop-down menu, (4) "Is" or "Is Not" as applicable in second drop-down menu and (5) select Hardware Version to specify in third drop-down menu. (6) Click "Next".  (7) Select "Notify" in first drop-down menu, (8) select "Send Email to Administrator" in second drop-down menu, and (9) enter email(s) of applicable administrators in box labeled "To:".  (10) Click "Next".  (11) Select appropriate information for Assignment of policy to particular platforms, groups, and/or users, and (12) click "Next".    (13) Click "Finish and Activate".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50083r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47317'
  tag rid: 'SV-60189r1_rule'
  tag stig_id: 'ARWA-01-000082'
  tag gtitle: 'SRG-APP-999-MDM-027-MDIS'
  tag fix_id: 'F-51023r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
