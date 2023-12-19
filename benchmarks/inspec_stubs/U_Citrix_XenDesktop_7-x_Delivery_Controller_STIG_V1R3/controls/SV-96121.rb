control 'SV-96121' do
  title 'Delivery Controller must be configured to disable non-essential capabilities.'
  desc 'It is detrimental for applications to provide or install by default functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to advertising software or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.'
  desc 'check', 'Verify Citrix Customer Experience Improvement Program (CEIP) - PHONE HOME is disabled on XenDesktop Delivery Controller.

1. Launch Studio.
2. Select "Configuration" in the left navigation pane.
3. Select the Support tab.
4. Verify CEIP is disabled.

If CEIP is not disabled, this is a finding.'
  desc 'fix', 'To disable Citrix CEIP - Phone Home:
1. Launch Studio.
2. Select "Configuration" in the left navigation pane.
3. Select the Support tab.
4. Follow the prompts to end participation in CEIP.

This prevents automatic upload of installation experience metrics that are collected locally during installation.
XenDesktopServerStartup.exe /components "CONTROLLER,DESKTOPSTUDIO"
/disableexperiencemetrics /exclude "Smart Tools Agent" /nosql
/quiet /verboselog /noreboot'
  impact 0.5
  ref 'DPMS Target XenDesktop 7.x Delivery Controller'
  tag check_id: 'C-81137r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81407'
  tag rid: 'SV-96121r1_rule'
  tag stig_id: 'CXEN-DC-000270'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-88213r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
