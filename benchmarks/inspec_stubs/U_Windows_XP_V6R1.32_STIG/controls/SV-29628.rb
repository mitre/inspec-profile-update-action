control 'SV-29628' do
  title 'Registry key auditing configuration does not meet minimum requirements.'
  desc 'Improper modification of the Registry can render a system useless.  Modifications to the Registry can have a significant impact on the security configuration of the system.  Auditing of significant modifications made to the Registry provides a method of determining the responsible party.'
  desc 'check', 'Verify system level auditing of object access is properly configured (see V-6850 “Audit object access”).  If this is not configured to audit “Failure”, this requirement is a finding.

Verify detailed registry auditing is configured.
Run “Regedit”. 
Navigate to the HKEY_LOCAL_MACHINE\\SOFTWARE and HKEY_LOCAL_MACHINE\\SYSTEM keys. 
On the menu bar, select “Edit” then “Permissions”. 
Click on the “Advanced” button. 
Select the “Auditing” tab. 
Verify the following is configured:
Type - Fail
Name - Everyone
Access - Full Control
Apply to - This key and subkeys

If the “Everyone” group, at a minimum is not being audited for all failures, this is a finding.'
  desc 'fix', 'Configure the HKEY_LOCAL_MACHINE\\SOFTWARE and HKEY_LOCAL_MACHINE\\SYSTEM keys to audit the Everyone Group for all failures. Audit settings should be propagated to subkeys.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-40667r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1088'
  tag rid: 'SV-29628r2_rule'
  tag gtitle: 'Registry Key Auditing'
  tag fix_id: 'F-28953r1_fix'
  tag false_positives: 'Sometimes audit settings may be incorrectly reported as findings.  If a manual review reveals that they are set properly, then this would not be a finding.'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-3'
end
