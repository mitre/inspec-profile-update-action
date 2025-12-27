control 'SV-239881' do
  title 'The Cisco ASA must be configured to queue log records locally In the event that the central audit server is down or not reachable.'
  desc 'It is critical that when the IDPS is at risk of failing to process audit logs as required, it take action to mitigate the failure.

Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure.

The IDPS performs a critical security function, so its continued operation is imperative. Since availability of the IDPS is an overriding concern, shutting down the system in the event of an audit failure should be avoided, except as a last resort. The SYSLOG protocol does not support automated synchronization, however this functionality may be provided by Network Management Systems (NMSs) which are not within the scope of this SRG.'
  desc 'check', 'Verify that TCP is being used to send log data to the syslog server.

Step 1: Navigate to Devices >> Platform Settings >> Syslog Servers.

Step 2: Verify that TCP is listed under the Protocol tab has been selected.

If the Cisco ASA is not configured to use TCP to send log data to the syslog server, this is a finding.'
  desc 'fix', 'Step 1: Navigate to Devices >> Platform Settings >> Syslog Servers.

Step 2: Click on the pencil icon to edit the applicable server.

Step 3: Select the TCP option.

Step 4: Click OK and Save.'
  impact 0.5
  ref 'DPMS Target Cisco ASA IPS'
  tag check_id: 'C-43114r665954_chk'
  tag severity: 'medium'
  tag gid: 'V-239881'
  tag rid: 'SV-239881r665956_rule'
  tag stig_id: 'CASA-IP-000130'
  tag gtitle: 'SRG-NET-000089-IDPS-00010'
  tag fix_id: 'F-43073r665955_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
