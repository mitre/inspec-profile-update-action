control 'SV-234212' do
  title 'The FortiGate device must implement cryptographic mechanisms using a FIPS 140-2 approved algorithm to protect the confidentiality of remote maintenance sessions.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Network, Interfaces.
2. Click the interface designated for device management traffic.
3. On Administrative Access, verify HTTPS and SSH are selected.

If HTTPS and SSH are not selected for administrative access, this is a finding.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command for all low privileged admin user:
     # show full-configuration system interface port{Management Port Integer #} | grep -i allowaccess

The output should include: 
          set allowaccess ping https ssh

If https and ssh are not returned, this is a finding. If http is returned, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Network, Interfaces.
2. Click the interface designated for device management traffic and pick Edit.
3. On Administrative Access, select HTTPS and SSH. Deselect HTTP.
4. Click OK.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command for all low privileged admin users:
     # config system interface 
     #    edit port{Management Port Integer #}
     #    set allowaccess ping https ssh
     # end

Note: When a protocol is added or removed, the entire list of protocols must be typed in again. For example, to add PING to an access list of HTTPS and SSH, use the following CLI command: 
     #   set allowaccess https ssh ping'
  impact 0.7
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37397r611823_chk'
  tag severity: 'high'
  tag gid: 'V-234212'
  tag rid: 'SV-234212r628777_rule'
  tag stig_id: 'FGFW-ND-000265'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-37362r611824_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
