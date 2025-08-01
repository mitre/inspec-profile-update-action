control 'SV-254190' do
  title 'Nutanix AOS must not be configured to allow KerberosAuthentication.'
  desc 'Failure to provide logical access restrictions associated with changes to system configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the operating system can have significant effects on the overall security of the system.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to operating system components for the purposes of initiating changes, including upgrades and modifications.

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Confirm Nutanix AOS enforces access restrictions.

Check that the SSH daemon does not permit Kerberos to authenticate passwords with the following command:

$ sudo grep -i kerberosauth /etc/ssh/sshd_config
KerberosAuthentication no

If the "KerberosAuthentication" keyword is missing, or is set to "yes" and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS to enforce access restrictions by running the following command.

$ sudo salt-call state.sls security/CVM/sshdCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57675r846656_chk'
  tag severity: 'medium'
  tag gid: 'V-254190'
  tag rid: 'SV-254190r846658_rule'
  tag stig_id: 'NUTX-OS-001020'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-57626r846657_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
