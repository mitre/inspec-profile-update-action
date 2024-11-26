control 'SV-227540' do
  title 'The Solaris system Automated Security Enhancement Tool (ASET) configurable parameters in the asetenv file must be correct.'
  desc 'If settings in the asetenv file have been modified, then system vulnerabilities may not be detected.'
  desc 'check', %q(Determine if ASET is being used.
	#	crontab -l | grep aset

Check the configuration of ASET.
	#	more /usr/aset/asetenv

OR

Check that asetenv has not been modified since installation.
        #      pkgchk SUNWast

If there are any changes below the following two lines that are not comments, this is a finding.

# Don't change from here on down ...      #
# there shouldn't be any reason to.           #

In addition, if any of the following lines do not match, this is a finding.
 
TASKS="firewall env sysconf usrgrp tune cklist eeprom"
CKLISTPATH_LOW=${ASETDIR}/tasks:#${ASETDIR} \
/util:${ASETDIR}/masters:/etc
CKLISTPATH_MED=${CKLISTPATH_LOW}:/usr/bin:/usr/ucb
CKLISTPATH_HIGH=${CKLISTPATH_MED}:/usr/lib:/sbin:  \
			/usr/sbin:/usr/ucblib
YPCHECK=false
PERIODIC_SCHEDULE="0 0 * * *"
UID_ALIASES=${ASETDIR}/masters/uid_aliases

(The default asetenv file can be found on the Solaris installation media.))
  desc 'fix', 'Restore the ASET configuration to vendor default and only modify the portions of the configuration designated as customizable.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29702r488150_chk'
  tag severity: 'medium'
  tag gid: 'V-227540'
  tag rid: 'SV-227540r603266_rule'
  tag stig_id: 'GEN000000-SOL00180'
  tag gtitle: 'SRG-OS-000016'
  tag fix_id: 'F-29690r488151_fix'
  tag 'documentable'
  tag legacy: ['V-953', 'SV-953']
  tag cci: ['CCI-000366', 'CCI-000032']
  tag nist: ['CM-6 b', 'AC-4 (8) (a)']
end
