control 'SV-234211' do
  title 'The FortiGate devices must use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of nonlocal maintenance and diagnostic communications.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. 

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.

Separate requirements for configuring applications and protocols used by each application (e.g., SNMPv3, SSHv2, NTP, HTTPS, and other protocols and applications that require server/client authentication) are required to implement this requirement. Where SSH is used, the SSHv2 protocol suite is required because it includes Layer 7 protocols such as SCP and SFTP, which can be used for secure file transfers.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Network, Interfaces.
2. Click the interface designated for device management traffic.
3. On Administrative Access, verify HTTPS and SSH are selected, and HTTP is not.

If HTTPS and SSH are not selected for administrative access, or HTTP is selected, this is a finding.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration system interface port{Management Port Integer #} | grep -i allowaccess

The output should include: 
          set allowaccess ping https ssh

If the allowaccess parameter does not include https and ssh, this is a finding. If the allowaccess parameter includes http, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Network, Interfaces
2. Click the interface designated for device management traffic and pick Edit.
3. On Administrative Access, select HTTPS and SSH. Deselect HTTP.
4. Click OK.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config system interface 
     #    edit port{Management Port Integer #}
     #    set allowaccess ping https ssh
     # end

Note: When adding or removing a protocol, the entire list of protocols must be typed again. For example, in an existing access list of HTTPS and SSH, if HTTP needs to be added, use the following CLI command: 
     #   set allowaccess https ssh ping http'
  impact 0.7
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37396r611820_chk'
  tag severity: 'high'
  tag gid: 'V-234211'
  tag rid: 'SV-234211r628777_rule'
  tag stig_id: 'FGFW-ND-000260'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-37361r611821_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
