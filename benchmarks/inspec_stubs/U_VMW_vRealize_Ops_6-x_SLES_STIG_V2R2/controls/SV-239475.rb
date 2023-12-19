control 'SV-239475' do
  title 'The SLES for vRealize must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited - ownership.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Check the permissions of the rules files in /etc/audit:

# ls -l /etc/audit/

Note: If /etc/audit/audit.rules is a symbolic link to /etc/audit/audit.rules.STIG, then the check is only applicable to /etc/audit/audit.rules.STIG.

If the ownership is not set to "root", this is a finding.'
  desc 'fix', 'Change the ownership of the /etc/audit/audit.rules.STIG, the /etc/audit/audit.rules.ORIG, and the /etc/audit/audit.rules files (if not a symbolic link):

# chown root /etc/audit/audit.rules.STIG
# chown root /etc/audit/audit.rules.ORIG
# if [ -f /etc/audit/audit.rules ]; then chown root /etc/audit/audit.rules; fi

Or run the following command to implement all logging requirements:

# /etc/dodscript.sh'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42708r661874_chk'
  tag severity: 'medium'
  tag gid: 'V-239475'
  tag rid: 'SV-239475r661876_rule'
  tag stig_id: 'VROM-SL-000245'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-42667r661875_fix'
  tag 'documentable'
  tag legacy: ['SV-99071', 'V-88421']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
