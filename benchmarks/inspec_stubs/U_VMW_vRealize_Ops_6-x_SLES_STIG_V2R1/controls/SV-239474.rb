control 'SV-239474' do
  title 'The SLES for vRealize must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited - Permissions.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Check the permissions of the rules files in /etc/audit:

# ls -l /etc/audit/

Note: If /etc/audit/audit.rules is a symbolic link to /etc/audit/audit.rules.STIG, then the check is only applicable to /etc/audit/audit.rules.STIG.

If the permissions of the file is not set to "640", this is a finding.'
  desc 'fix', 'Change the permissions of the /etc/audit/audit.rules.STIG, the /etc/audit/audit.rules.ORIG, and the /etc/audit/audit.rules files (if not a symbolic link):

# chmod 640 /etc/audit/audit.rules.STIG
# chmod 640 /etc/audit/audit.rules.ORIG
# if [ -f /etc/audit/audit.rules ]; then chmod 640 /etc/audit/audit.rules; fi

Or run the following command to implement all logging requirements:

# /etc/dodscript.sh'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42707r661871_chk'
  tag severity: 'medium'
  tag gid: 'V-239474'
  tag rid: 'SV-239474r661873_rule'
  tag stig_id: 'VROM-SL-000240'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-42666r661872_fix'
  tag 'documentable'
  tag legacy: ['SV-99069', 'V-88419']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
