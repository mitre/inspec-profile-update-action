control 'SV-246856' do
  title 'The HYCU server must use FIPS-validated algorithms for authentication to a cryptographic module and Keyed-Hash Message Authentication Code (HMAC) to protect the integrity and confidentiality of remote maintenance sessions.'
  desc 'Unapproved algorithms used by the cryptographic module are not validated and therefore cannot be relied on to provide confidentiality or integrity, and DoD data may be compromised.

Remote maintenance and diagnostic activities are activities conducted by individuals communicating through an external network (e.g., the internet) or an internal network. 

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. However, authentication algorithms must configure security processes to use only FIPS-approved and NIST-recommended authentication algorithms.

This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.

'
  desc 'check', %q(When FIPS mode is enabled, the HYCU application will use FIPS-compliant behavior. Validation of FIPS status can be done using the following commands:
'cat /proc/sys/crypto/fips_enabled' 

If command output does not show "1", this is a finding.

'fips-mode-setup --check'

If command output does not show "FIPS mode is enabled", this is a finding.

'update-crypto-policies --show'

If command output does not show "FIPS", this is a finding.)
  desc 'fix', 'Stop the HYCU web server: 
sudo systemctl stop grizzly.service

Enable FIPS-compliant mode: 
sudo /opt/grizzly/bin/enable_fips.sh

Reboot the HYCU virtual machines:
shutdown -r now'
  impact 0.7
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50288r768230_chk'
  tag severity: 'high'
  tag gid: 'V-246856'
  tag rid: 'SV-246856r768232_rule'
  tag stig_id: 'HYCU-IA-000008'
  tag gtitle: 'SRG-APP-000179-NDM-000265'
  tag fix_id: 'F-50242r768231_fix'
  tag satisfies: ['SRG-APP-000179-NDM-000265', 'SRG-APP-000411-NDM-000330', 'SRG-APP-000412-NDM-000331']
  tag 'documentable'
  tag cci: ['CCI-000803', 'CCI-002890', 'CCI-003123']
  tag nist: ['IA-7', 'MA-4 (6)', 'MA-4 (6)']
end
