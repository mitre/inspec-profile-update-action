control 'SV-104421' do
  title 'The SEL-2740S must employ automated mechanisms to assist in the tracking of security incidents.'
  desc "Despite the investment in perimeter defense technologies, enclaves are still faced with detecting, analyzing, and remediating network breaches and exploits that have made it past the network device. An automated incident response infrastructure allows network operations to immediately react to incidents by identifying, analyzing, and mitigating any network device compromise. Incident response teams can perform root cause analysis, determine how the exploit proliferated, and identify all affected nodes, as well as contain and eliminate the threat.

The network device assists in the tracking of security incidents by logging detected security events. The audit log and network device application logs capture different types of events. The audit log tracks audit events occurring on the components of the network device. The application log tracks the results of the network device content filtering function. These logs must be aggregated into a centralized server and can be used as part of the organization's security incident tracking and analysis."
  desc 'check', 'Verify that the switch is configured to use a syslog server for the purpose of forwarding alerts to the administrators and the ISSO.

1. Login with Permission Level 3 into the OTSDN Controller.
2. Go to the Configuration Object page and select the subject switch node.
3. Check the log services settings and confirm hat a syslog server IP address is in the settings fields.

If the SEL-2740S is not configured to use a syslog server, this is a finding.'
  desc 'fix', 'To configure the SEL-2740S to send logs to Syslog servers do the following:

1. Login with Permission Level 3 right into parent OTSDN Controller.
2. Go to the Configuration Objects settings page and select the desired switch.
3. Insert the Syslog log service and configure the settings with the desired IP addresses into the syslog settings fields.
4. Create the flow rules necessary for syslog.'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch NDM'
  tag check_id: 'C-93781r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94591'
  tag rid: 'SV-104421r2_rule'
  tag stig_id: 'SELS-ND-001400'
  tag gtitle: 'SRG-APP-000516-NDM-000342'
  tag fix_id: 'F-100709r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000833']
  tag nist: ['CM-6 b', 'IR-5 (1)']
end
