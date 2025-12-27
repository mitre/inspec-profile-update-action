control 'SV-221494' do
  title 'OHS utilizing mobile code must meet DoD-defined mobile code requirements.'
  desc "Mobile code in hosted applications allows the developer to add functionality and displays to hosted applications that are fluid, as opposed to a static web page. The data presentation becomes more appealing to the user, is easier to analyze, and navigation through the hosted application and data is much less complicated.

Some mobile code technologies in use in today's applications are: Java, JavaScript, ActiveX, PDF, Postscript, Shockwave movies, Flash animations, and VBScript. The DoD has created policies that define the usage of mobile code on DoD systems. The usage restrictions and implementation guidance apply to both the selection and use of mobile code installed on organizational servers and mobile code downloaded and executed on individual workstations.

The web server may host applications that contain mobile code and therefore, must meet the DoD-defined requirements regarding the deployment and/or use of mobile code. This includes digitally signing applets in order to provide a means for the client to establish application authenticity."
  desc 'check', '1. Check to see whether OHS is hosting any applications that use mobile code.

2. If so, check that the mobile code follows DoD policies regarding the acquisition, development, and/or use of mobile code.

3. If not, this is a finding.'
  desc 'fix', 'Ensure that any mobile code used by any of the applications hosted on OHS follow DoD policies regarding the acquisition, development, and/or use.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23209r415165_chk'
  tag severity: 'medium'
  tag gid: 'V-221494'
  tag rid: 'SV-221494r415167_rule'
  tag stig_id: 'OH12-1X-000265'
  tag gtitle: 'SRG-APP-000206-WSR-000128'
  tag fix_id: 'F-23198r415166_fix'
  tag 'documentable'
  tag legacy: ['SV-78937', 'V-64447']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
