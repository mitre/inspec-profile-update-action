control 'SV-243448' do
  title 'A Windows update service must be available to provide software updates for the PAW platform.'
  desc 'Older versions of operating systems usually contain vulnerabilities that have been fixed in later versions. In addition, most operating system patches contain fixes for recently discovered security vulnerabilities. Due to the highly privileged activities of a PAW, it must be maintained at the highest security posture possible and therefore must have the latest operating system updates installed.

Because a PAW is isolated from online operating system update services, a software update service must be available on the intranet to manage operating system and other software updates for site PAWs. A separate software update service is not required at each tier.'
  desc 'check', 'Verify an automated software update service is being used at the site to update the operating system of site PAWs.

If an automated software update service is not set up and configured to provide updates to site PAWs, this is a finding.'
  desc 'fix', 'Install a Windows update service (for example, Microsoft WSUS or System Center Configuration Manager [SCCM]) to provide software updates to all Windows-based PAWs in the organization.

Configure the Windows update service to download available operating system updates and install them when approved.

Based on site policy, configure the Windows update service to either automatically approve new updates for installation or to not install updates until installation is initiated by an authorized PAW maintenance administrator.

If WSUS is being used, configure Windows Update for WSUS on each PAW (use appropriate configuration procedures if an alternate Windows update service is used).

Go to Computer Configuration\\Administrative Templates\\Windows Components\\Windows Updates and follow the steps below:

1. Enable the Configure Automatic Updates policy.
2. Select option 4 - Auto download and schedule the install.
3. Change the option "Scheduled install day" to "0 - Every Day" and the option "Scheduled install time" to your organizational preference.
4. Enable option "Specify intranet Microsoft update service location" policy, and specify in both options the URL of the WSUS server.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows PAW'
  tag check_id: 'C-46723r722913_chk'
  tag severity: 'medium'
  tag gid: 'V-243448'
  tag rid: 'SV-243448r722915_rule'
  tag stig_id: 'WPAW-00-000800'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-46680r722914_fix'
  tag 'documentable'
  tag legacy: ['V-78153', 'SV-92859']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
