control 'SV-242655' do
  title 'The Cisco ISE must verify the checksum value of any software download, including install files (ISO or OVA), patch files, and upgrade bundles.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network.

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.

Separate requirements for configuring applications and protocols used by each application (e.g., SNMPv3, SSHv2, NTP, HTTPS, and other protocols and applications that require server/client authentication) are required to implement this requirement. Where SSH is used, the SSHv2 protocol suite is required because it includes Layer 7 protocols such as SCP and SFTP, which can be used for secure file transfers.'
  desc 'check', 'Verify the SSP requires a process for verifying the checksum for software download and install ISO files.

If a local documented process does not require that the checksum value of any software download be verified, this is a finding.'
  desc 'fix', 'Go to the DoD repository or Cisco download page. Hover over the download link and a small window will pop up. This window will contain information about that particular download. The information includes the MD5 and SHA512 checksum value of that file.

From the Cisco ISE command line interface (CLI), enter application upgrade prepare command. This command copies the upgrade bundle to the local repository "upgrade" that you created in the previous step and lists the MD5 and SHA256 checksum.

If the checksum matches the value found from the source repository, proceed with the update.'
  impact 0.7
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45930r714273_chk'
  tag severity: 'high'
  tag gid: 'V-242655'
  tag rid: 'SV-242655r879784_rule'
  tag stig_id: 'CSCO-NM-000500'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-45887r714274_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
