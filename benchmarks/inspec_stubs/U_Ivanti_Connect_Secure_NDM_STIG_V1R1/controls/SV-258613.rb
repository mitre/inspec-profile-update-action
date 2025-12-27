control 'SV-258613' do
  title 'The ICS must be configured to run an operating system release that is currently supported by Ivanti.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.'
  desc 'check', 'Navigate to the ICS support site https://my.pulsesecure.net/.
1. Login using the valid support login.
2. Click the link for "Software Licensing and Download".
3. Click "License and System Download".
4. Click "Software Download".
5. Under "Product Lines", click "Pulse Connect Secure" and again, "Pulse Connect Secure".
6. Click the "End of Support" tab.
7. Now using the ICS Web UI, navigate to Maintenance >> System >> Platform.

If the version running under Current Version is on the list of End of Support images on the Ivanti support site, this is a finding.'
  desc 'fix', %q(Navigate to the ICS support site https://my.pulsesecure.net/.
1. Login using the valid support login.
2. Click the link for "Software Licensing and Download".
3. Click either virtual or physical appliance.
4. Click "Software Download".
5. Under Product Lines, click "Pulse Connect Secure" and again, "Pulse Connect Secure".
6. Click "Current and Supported Releases".
7. Click "Download" on the latest ICS images.

Using the ICS Web UI navigate to Maintenance >> System >> Upgrade/Downgrade.
1. Ensure the ICS is upgraded in accordance with the site's change management and change control policies, as this will cause a platform outage.
2. Under "Install Service Package" click "Browse" and select the recently downloaded images.
3. Click "Install".
4. Follow all prompts for the upgrading the new images.)
  impact 0.7
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62353r930525_chk'
  tag severity: 'high'
  tag gid: 'V-258613'
  tag rid: 'SV-258613r930527_rule'
  tag stig_id: 'IVCS-NM-000410'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-62262r930526_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
