control 'SV-80997' do
  title 'The Juniper SRX Services Gateway must ensure access to start a UNIX-level shell is restricted to only the root account.'
  desc 'Restricting the privilege to create a UNIX-level shell limits access to this powerful function. System administrators, regardless of their other permissions, will need to also know the root password for this access, thus limiting the possibility of malicious or accidental circumvention of security controls.'
  desc 'check', 'Verify each login class is configured to deny access to the UNIX shell.

[edit]
show system login

If each configured login class is not configured to deny access to the UNIX shell, this is a finding.'
  desc 'fix', 'For each login class, add the following command to the stanza.

[edit]
set system login class <class name> deny-commands "(start shell)"'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67151r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66507'
  tag rid: 'SV-80997r1_rule'
  tag stig_id: 'JUSX-DM-000113'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-72581r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
