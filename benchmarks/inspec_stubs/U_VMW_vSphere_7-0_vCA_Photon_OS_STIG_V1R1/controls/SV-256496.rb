control 'SV-256496' do
  title 'The Photon operating system must allow only the information system security manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict the roles and individuals that can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'At the command line, run the following command:

# find /etc/audit/* -type f -exec stat -c "%n permissions are %a" {} $1\\;

If the permissions of any files are more permissive than "640", this is a finding.'
  desc 'fix', 'At the command line, run the following command:

# chmod 640 <file>

Replace <file> with any file with incorrect permissions.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCA Photon OS'
  tag check_id: 'C-60171r887160_chk'
  tag severity: 'medium'
  tag gid: 'V-256496'
  tag rid: 'SV-256496r887162_rule'
  tag stig_id: 'PHTN-30-000019'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-60114r887161_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
