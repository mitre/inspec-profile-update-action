control 'SV-87257' do
  title 'The Cassandra database must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Check the Cassandra Server settings and documentation to determine whether designated personnel are able to select which auditable events are being audited.

At the command prompt, execute the following command:

# ls -al /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If the permissions are not "0640", this is a finding.'
  desc 'fix', 'Configure the Cassandra Server settings to allow designated personnel to select which auditable events are audited.

At the command line execute the following command:

# chmod 0640 /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72779r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72625'
  tag rid: 'SV-87257r1_rule'
  tag stig_id: 'VROM-CS-000015'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-79027r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
