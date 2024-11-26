control 'SV-33016' do
  title 'The site software used with the web server must have all applicable security patches applied and documented.'
  desc 'The IAVM process does not address all patches that have been identified for the host operating system or, in this case, the web server software environment. Many vendors have subscription services available to notify users of known security threats. The site needs to be aware of these fixes and make determinations based on local policy and what software features are installed, if these patches need to be applied. 

In some cases, patches also apply to middleware and database systems. Maintaining the security of web servers requires frequent reviews of security notices. Many security notices mandate the installation of a software patch to overcome security vulnerabilities. 

SAs and ISSOs should regularly check the vendor support web site for patches and information related to the web server software. All applicable security patches will be applied to the operating system and to the web server software. Security patches are deemed applicable if the product is installed, even if it is not used or is disabled.'
  desc 'check', 'Query the web administrator to determine if the site has a detailed process as part of its configuration management plan to stay compliant with all security-related patches.

Proposed Questions:

How does the SA stay current with web server vendor patches?
How is the SA notified when a new security patch is issued by the vendor? (Exclude the IAVM.)
What is the process followed for applying patches to the web server?

If the site is not in compliance with all applicable security patches, this is a finding.'
  desc 'fix', 'Establish a detailed process as part of the configuration management plan to stay compliant with all web server security-related patches.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33698r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13613'
  tag rid: 'SV-33016r2_rule'
  tag stig_id: 'WA230 W22'
  tag gtitle: 'WA230'
  tag fix_id: 'F-29323r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSC-1'
end
