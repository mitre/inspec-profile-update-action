control 'SV-99689' do
  title 'tc Server ALL log files must be moved to a permanent repository in accordance with site policy.'
  desc "A web server will typically utilize logging mechanisms for maintaining a historical log of activity that occurs within a hosted application. This information can then be used for diagnostic purposes, forensics purposes, or other purposes relevant to ensuring the availability and integrity of the hosted application.

Log files must be periodically moved from the web server to a permanent storage location. This serves two beneficial purposes. First, the web server's resources are freed up for productions. Also, this ensures that the site has, and enforces, policies designed to preserve the integrity of historical logs."
  desc 'check', 'Obtain supporting documentation from the ISSO.

Review the site policy for moving log files from the web server to a permanent repository. Ensure that log files are being moved from the web server in accordance with the site policy.

If the site does not have a policy for periodically moving log files to an archive repository or such policy is not being enforced, this is a finding.'
  desc 'fix', 'Develop and enforce a site policy for moving log files periodically from the web server to a permanent repository in accordance with site retention policies.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88731r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89039'
  tag rid: 'SV-99689r1_rule'
  tag stig_id: 'VROM-TC-000790'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag fix_id: 'F-95781r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
