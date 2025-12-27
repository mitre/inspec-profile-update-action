control 'SV-217189' do
  title 'The SUSE operating system must be configured to not overwrite Pluggable Authentication Modules (PAM) configuration on package changes.'
  desc '"pam-config" is a command line utility that automatically generates a system PAM configuration as packages are installed, updated or removed from the system. "pam-config" removes configurations for PAM modules and parameters that it does not know about. It may render ineffective PAM configuration by the system administrator and thus impact system security.'
  desc 'check', 'Verify the SUSE operating system is configured to not overwrite Pluggable Authentication Modules (PAM) configuration on package changes.

Check that soft links between PAM configuration files are removed with the following command:

> find /etc/pam.d/ -type l -iname "common-*"

If any results are returned, this is a finding.'
  desc 'fix', "Copy the PAM configuration files to their static locations and remove the SUSE operating system soft links for the PAM configuration files with the following command:

> sudo sh -c 'for X in /etc/pam.d/common-*-pc; do cp -ivp --remove-destination $X ${X:0:-3}; done'

Additional information on the configuration of multifactor authentication on the SUSE operating system can be found at https://www.suse.com/communities/blog/configuring-smart-card-authentication-suse-linux-enterprise/."
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18417r646735_chk'
  tag severity: 'medium'
  tag gid: 'V-217189'
  tag rid: 'SV-217189r646737_rule'
  tag stig_id: 'SLES-12-010910'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18415r646736_fix'
  tag 'documentable'
  tag legacy: ['SV-91981', 'V-77285']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
