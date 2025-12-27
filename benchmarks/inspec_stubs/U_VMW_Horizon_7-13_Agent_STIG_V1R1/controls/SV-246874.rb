control 'SV-246874' do
  title 'The Horizon Agent must block USB mass storage.'
  desc 'The Horizon Agent has the capability to granularly control what, if any, USB devices are allowed to be passed from the local client to the agent on the virtual desktop. By default, Horizon blocks certain device families from being redirected to the remote desktop or application. For example, HID (human interface devices) and keyboards are blocked from appearing in the guest as released BadUSB code targets USB keyboard devices.

While there are legitimate reasons to pass USB devices to the desktop, these must be carefully analyzed for necessity. At a minimum, USB Mass Storage devices must never passed through, in keeping with long-standing DoD data loss prevention policies. As thumb drives are disallowed for physical PCs, so should they be for virtual desktops. This can be accomplished in many ways, including natively in the Horizon Agent.'
  desc 'check', 'Interview the SA. USB mass storage devices can be blocked in a number of ways:

1. The desktop OS
2. A third party DLP solution
3. The "USB Redirection" optional agent feature not being installed on any VDI image
4. On the Connection Server via individual pool policies or global policies

If any of these methods are already employed, the risk is already addressed and this control is not applicable.

If USB devices are not otherwise blocked, the Horizon agent must be configured to block storage devices via allowlist or denylist.

Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> View USB Configuration.

1. Check for denylisting:

Double-click the "Exclude Device Family" setting.

If "Exclude Device Family" is not "Enabled", denylisting is Not Configured.

If "Exclude Device Family" does not include at least "o:storage", denylisting is Not Configured.

If denylisting is Not Configured, continue to check for allowlisting. If denylisting is configured, this is not a finding.

2. Check for allowlisting:

Double-click the "Exclude All Devices" setting.

If "Exclude All Devices" is not "Enabled", allowlisting is Not Configured.

Click "Cancel". Double-click the "Include Device Family" setting. If "Include Device Family" is "Enabled" and includes "storage", allowlisting is Not Configured.

If neither denylisting nor allowlisting is properly configured, this is a finding.'
  desc 'fix', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> View USB Configuration.

Option 1, denylist:

Double-click the "Exclude Device Family" setting.

If the setting is "Disabled" or "Not Configured", click the radio button next to "Enabled".

In the field below "Exclude Device Family", add the following:

o:storage

Click "OK".

Option 2, allowlist:

Double-click the "Exclude All Devices" setting.

If the setting is "Disabled" or "Not Configured", click the radio button next to "Enabled". Click "OK".

(Optional)

Double-click the "Include Device Family" setting.

Make sure the setting is "Enabled".

In the field below "Include Device Family", add the site-specific allowlisted device family strings, making sure to not include any "storage".

Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Agent'
  tag check_id: 'C-50306r790570_chk'
  tag severity: 'medium'
  tag gid: 'V-246874'
  tag rid: 'SV-246874r768582_rule'
  tag stig_id: 'HRZA-7X-000015'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50260r790571_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
