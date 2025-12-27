control 'SV-217262' do
  title 'SuSEfirewall2 must protect against or limit the effects of Denial-of-Service (DoS) attacks on the SUSE operating system by implementing rate-limiting measures on impacted network interfaces.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of the SUSE operating system to mitigate the impact on system availability of DoS attacks that have occurred or are ongoing. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Verify "SuSEfirewall2" is configured to protect the SUSE operating system against or limit the effects of DoS attacks. 

Run the following command:

# grep -i fw_services_accept_ext /etc/sysconfig/SuSEfirewall2
FW_SERVICES_ACCEPT_EXT="0/0,tcp,22,,hitcount=3,blockseconds=60,recentname=ssh"

If the "FW_SERVICES_ACCEPT_EXT" rule does not contain both the "hitcount" and "blockseconds" parameters, this is a finding.'
  desc 'fix', 'Configure "SuSEfirewall2" to protect the SUSE operating system against or limit the effects of DoS attacks by implementing rate-limiting measures on impacted network interfaces.

Add or replace the following line in "/etc/sysconfig/SuSEfirewall2":

FW_SERVICES_ACCEPT_EXT="0/0,tcp,22,,hitcount=3,blockseconds=60,recentname=ssh"

The firewall must be restarted in order for the changes to take effect.

# sudo systemctl restart SuSEfirewall2.service'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18490r369942_chk'
  tag severity: 'high'
  tag gid: 'V-217262'
  tag rid: 'SV-217262r603262_rule'
  tag stig_id: 'SLES-12-030040'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-18488r369943_fix'
  tag 'documentable'
  tag legacy: ['SV-92133', 'V-77437']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
