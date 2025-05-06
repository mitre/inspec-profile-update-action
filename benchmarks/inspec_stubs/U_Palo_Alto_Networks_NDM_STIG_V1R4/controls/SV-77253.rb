control 'SV-77253' do
  title 'The Palo Alto Networks security platform must allow the use of a temporary password for system logons with an immediate change to a permanent password.'
  desc 'Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial logon.

Temporary passwords are typically used to allow access to applications when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts that allow the users to log on yet force them to change the password once they have successfully authenticated.'
  desc 'check', 'Go to Device >> Setup >> Management
View the "Minimum Password Complexity" window.
If the "Require Password Change on First Login" box is not selected, this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Management
In the "Minimum Password Complexity" window, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
Select the "Require Password Change on First Login" box.
Check the "Enabled" box, then select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63571r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62763'
  tag rid: 'SV-77253r1_rule'
  tag stig_id: 'PANW-NM-000114'
  tag gtitle: 'SRG-APP-000397-NDM-000312'
  tag fix_id: 'F-68683r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
