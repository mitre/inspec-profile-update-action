control 'SV-234208' do
  title 'The FortiGate device must use LDAPS for the LDAP connection.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Network devices can accomplish this by making direct function calls to encryption modules or by leveraging operating system encryption capabilities.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration user ldap | grep -i ldaps
The output should be:         
          set secure ldaps

If set secure is not set to ldaps, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config user ldap
           # edit {ldap_server_name}
           # set server {server_ip}
           # set cnid {cn} 
           # set dn {dc=XYZ,dc=fortinet,dc=COM} 
           # set type regular 
           # set username {cn=Administrator,dc=XYA, dc=COM} 
           # set password {bind password}
           # set secure ldaps
           #    set ca-cert {CA certificate name}
      # next 
  # end'
  impact 0.7
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37393r611811_chk'
  tag severity: 'high'
  tag gid: 'V-234208'
  tag rid: 'SV-234208r628777_rule'
  tag stig_id: 'FGFW-ND-000245'
  tag gtitle: 'SRG-APP-000172-NDM-000259'
  tag fix_id: 'F-37358r611812_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
