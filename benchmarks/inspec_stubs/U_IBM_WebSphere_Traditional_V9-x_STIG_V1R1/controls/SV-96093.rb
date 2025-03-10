control 'SV-96093' do
  title 'The WebSphere Application servers with an RMF categorization of high must be in a high-availability (HA) cluster.'
  desc 'This requirement is dependent upon system MAC and confidentiality. If the system MAC and confidentiality levels do not specify redundancy requirements, this requirement is NA.

Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. When application failure is encountered, preserving application state facilitates application restart and return to the operational mode of the organization with less disruption of mission/business processes.

Clustering of multiple application servers is a common approach to providing fail-safe application availability when system MAC and confidentiality levels require redundancy.

'
  desc 'check', 'Review Systems Security Plan and identify system categorization.

If the system is not categorized as HIGH, this requirement is NA.

In the administrative console, click Servers >> Clusters >> WebSphere application server clusters.

Ensure you have a cluster defined, if not this is a finding.'
  desc 'fix', 'In the administrative console, click Servers >> Clusters >> WebSphere application server clusters >> New.

Specify a name for the cluster.

Click "Next".

Specify the name of the first cluster member.

Select the node on which you want this cluster member to reside, leave remaining fields as default.

Click "Next".

Create additional cluster members as needed (give unique name for each member and click "Add Member"), when finished adding members click "Next".

Click "Finish" to create the cluster.

Click "Save".

Refer to vendor documentation that provides direction on the creation of clusters for specific details.

Restart DMGR and sync all JVMs.'
  impact 0.3
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81089r1_chk'
  tag severity: 'low'
  tag gid: 'V-81379'
  tag rid: 'SV-96093r1_rule'
  tag stig_id: 'WBSP-AS-001480'
  tag gtitle: 'SRG-APP-000225-AS-000154'
  tag fix_id: 'F-88165r1_fix'
  tag satisfies: ['SRG-APP-000225-AS-000154', 'SRG-APP-000435-AS-000069']
  tag 'documentable'
  tag cci: ['CCI-001190', 'CCI-002385']
  tag nist: ['SC-24', 'SC-5 a']
end
