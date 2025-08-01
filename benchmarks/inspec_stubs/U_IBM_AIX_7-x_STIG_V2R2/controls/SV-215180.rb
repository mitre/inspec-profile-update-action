control 'SV-215180' do
  title 'The AIX system must automatically remove or disable emergency accounts after the crisis is resolved or 72 hours.'
  desc "Emergency accounts are privileged accounts that are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability. 

Emergency accounts are different from infrequently used accounts (i.e., local login accounts used by the organization's system administrators when network or normal login/access is not available). Infrequently used accounts are not subject to automatic termination dates.  Emergency accounts are accounts created in response to crisis situations, usually for use by maintenance personnel. The automatic expiration or disabling time period may be extended as needed until the crisis is resolved; however, it must not be extended indefinitely. A permanent account should be established for privileged users who need long-term maintenance accounts.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements."
  desc 'check', 'Obtain a list of emergency accounts from the ISSO/ISSM and then run this command against each of the identified accounts:
# lsuser -a expires <emergency_user>

The above command should yield the following output:
<emergency_user> expires=0
Or
<emergency_user> expires=1215103116

The "expires" value parameter is a 10-character string in the MMDDhhmmyy form, where MM = month, DD = day, hh = hour, mm = minute, and yy = last 2 digits of the years 1939 through 2038. All characters are numeric. If the Value parameter is 0, the account does not expire.

If "expires" value is "0", or the expiration time is greater than "72" hours from the user creation time, this is a finding.'
  desc 'fix', 'From the command prompt, run the following command to set the "expires" value to "72" hours from now:
# chuser expires=1228093516 <emergency_user>

The "expires" value parameter is a 10-character string in the MMDDhhmmyy form, where MM = month, DD = day, hh = hour, mm = minute, and yy = last 2 digits of the years 1939 through 2038. All characters are numeric.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16378r293991_chk'
  tag severity: 'medium'
  tag gid: 'V-215180'
  tag rid: 'SV-215180r508663_rule'
  tag stig_id: 'AIX7-00-001014'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag fix_id: 'F-16376r293992_fix'
  tag 'documentable'
  tag legacy: ['SV-101535', 'V-91437']
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
