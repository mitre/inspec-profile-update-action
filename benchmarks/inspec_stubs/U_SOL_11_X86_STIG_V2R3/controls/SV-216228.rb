control 'SV-216228' do
  title 'The operating system must prevent the execution of prohibited mobile code.'
  desc 'Decisions regarding the employment of mobile code within operating systems are based on the potential for the code to cause damage to the system if used maliciously. 

Mobile code technologies include Java, JavaScript, ActiveX, PDF, Postscript, Shockwave movies, Flash animations, and VBScript. Usage restrictions and implementation guidance apply to both the selection and use of mobile code installed on organizational servers and mobile code downloaded and executed on individual workstations.'
  desc 'check', %q(Determine if the Firefox package is installed:

# pkg list web/browser/firefox

If the package is not installed, this check does not apply.

If installed, ensure that it is a supported version.

# pkg info firefox | grep Version
Version: 52.5.2

If the version is not supported, this is a finding.

Ensure that Java and JavaScript access by Firefox are disabled.

Start Firefox.

In the address bar type: about:config

In search bar type: javascript.enabled

If 'Value" is true, this is a finding

In the address bar type: about:addons

Click on "I accept the risk" button.

Click on "Plugins".

If Java is enabled, this is a finding.)
  desc 'fix', 'In the address bar type: about:config

Click on "I accept the risk" button.

In search bar type: javascript.enabled

Double click on the javascript.enabled and Value true will change to false.

In the address bar type: about:addons

Click on "Plugins".

If Java is displayed, disable Java by clicking on the 
Never Activate selection'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17466r373066_chk'
  tag severity: 'medium'
  tag gid: 'V-216228'
  tag rid: 'SV-216228r603268_rule'
  tag stig_id: 'SOL-11.1-090100'
  tag gtitle: 'SRG-OS-000181'
  tag fix_id: 'F-17464r373067_fix'
  tag 'documentable'
  tag legacy: ['V-47969', 'SV-60841']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
