control 'SV-86197' do
  title 'The CA API Gateway must employ automated mechanisms to assist in the tracking of security incidents.'
  desc "Despite the investment in perimeter defense technologies, enclaves are still faced with detecting, analyzing, and remediating network breaches and exploits that have made it past the network device. An automated incident response infrastructure allows network operations to immediately react to incidents by identifying, analyzing, and mitigating any network device compromise. Incident response teams can perform root cause analysis, determine how the exploit proliferated, and identify all affected nodes, as well as contain and eliminate the threat.

The network device assists in the tracking of security incidents by logging detected security events. The audit log and network device application logs capture different types of events. The audit log tracks audit events occurring on the components of the network device. The application log tracks the results of the network device content filtering function. These logs must be aggregated into a centralized server and can be used as part of the organization's security incident tracking and analysis."
  desc 'check', 'Verify the CA API Gateway forwards all log audit log messages to the central log server. 

Within the "/etc/rsyslog.conf" file, confirm a rule in the format "*.* @@loghost.log.com" is in the ruleset section.

If the CA API Gateway "/etc/rsyslog.conf" file does not have a rule in the format "*.* @@loghost.log.com" in the ruleset section, this is a finding.'
  desc 'fix', 'Configure the CA API Gateway to forward all log audit log messages to the central log server.

- Log in to CA API Gateway as root.
- Open "/etc/rsyslog.conf" for editing.
- Add a rule "*.* @@loghost.log.com" to the ruleset section of the rsyslogd.conf file.'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71951r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71573'
  tag rid: 'SV-86197r1_rule'
  tag stig_id: 'CAGW-DM-000400'
  tag gtitle: 'SRG-APP-000516-NDM-000342'
  tag fix_id: 'F-77897r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000833']
  tag nist: ['CM-6 b', 'IR-5 (1)']
end
