control 'SV-88657' do
  title 'The Cisco IOS XE router must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify that the Cisco IOS XE router is configured to only allow individuals in the proper role to select audited events.

The configuration should look similar to the example below:

parser view Senior-Admin
 secret 5 $1$hW3m$PE.3zCJYeSrvYflFey71R.
 commands exec include all configure
 commands exec include all show

parser view Auditor
 secret 5 $1$qb3F$SrdJW2oyyDzq1L94I7eED.
 commands exec include show logging

If this is not configured, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router using the following commands:

parser view Senior-Admin
 secret 5 $1$hW3m$PE.3zCJYeSrvYflFey71R.
 commands exec include all configure
 commands exec include all show

parser view Auditor
 secret 5 $1$qb3F$SrdJW2oyyDzq1L94I7eED.
 commands exec include show logging'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74065r3_chk'
  tag severity: 'low'
  tag gid: 'V-73983'
  tag rid: 'SV-88657r2_rule'
  tag stig_id: 'CISR-ND-000024'
  tag gtitle: 'SRG-APP-000090-NDM-000222'
  tag fix_id: 'F-80523r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
