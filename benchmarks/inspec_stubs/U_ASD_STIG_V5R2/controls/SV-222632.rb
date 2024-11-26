control 'SV-222632' do
  title 'A Software Configuration Management (SCM) plan describing the configuration control and change management process of application objects developed by the organization and the roles and responsibilities of the organization must be created and maintained.'
  desc 'Software Configuration Management (SCM) is very important in tracking code releases, baselines, and managing access to the configuration management repository. The SCM plan identifies what should be under configuration management control.

Without an SCM plan that addresses code security issues, code releases can be tracked and vulnerabilities can be inserted intentionally or unintentionally into the code base of the application.

This requirement is intended to be applied to application developers or organizations responsible for code management or who have and operate an application configuration management repository (CMR).

The SCM plan identifies all objects created during the development process subject to configuration control.

The SCM plan maintains procedures for identifying individual application components, as well as, entire application releases during all phases of the software development lifecycle.

The SCM plan identifies and tracks all actions and changes resulting from a change request from initiation to release.

The SCM plan contains procedures to identify, document, review, and authorize any change requests to the application.

The SCM plan defines the responsibilities, the actions to be performed, the tools, techniques and methodologies, and defines an initial set of baselined software components.

The SCM plan objects have security classifications labels.

The SCM plan identifies tools and version numbers used in the software development lifecycle.

The SCM plan identifies mechanisms for controlled access of simultaneous individuals updating the same application component.

The SCM plan assures only authorized changes by authorized persons are possible.

The SCM plan identifies mechanisms to control access and audit changes between different versions of objects subject to configuration control.

The SCM plan identifies mechanisms to track and audit all modifications of objects under configuration control.  Audits include the originator and date and time of the modification.

The SCM plan should contain the following:

- Description of the configuration control and change management process
- Types of objects developed
- Roles and responsibilities of the organization

The SCM plan should also contain the following:

- Defined responsibilities
- Actions to be performed
- Tools used in the process
- Techniques and methodologies
- Initial set of baselined software components

The SCM plan should identify all objects that are under configuration management control.

The SCM plan should identify third-party tools and respective version numbers.

The SCM plan should identify mechanisms for controlled access of individuals simultaneously updating the same application component.

The SCM plan assures only authorized changes by authorized persons are allowed.

The SCM plan should identify mechanisms to control access and audit changes between different versions of objects subject to configuration control.

The SCM plan should have procedures for label versions of application components and application builds under configuration management control.

The configuration management repository (CMR) should track change requests from beginning to end.

The configuration management repository (CMR) should authorize change requests to the application.
 
The configuration management repository (CMR) should contain security classification labels for code and documentation in the repository. Classification labels are not applicable to unclassified systems.

The configuration management repository (CMR) should monitor all objects under CMR control for auditing.'
  desc 'check', 'Interview ISSM or application administrator.

Identify if development of the application is done in house and if application configuration management repository exists.

If application development is not done in house and if a code configuration management repository does not exist, the requirement is not applicable.

Verify the SCM plan identifies all objects created during the development process subject to configuration control.

Verify the SCM plan maintains procedures for identifying individual application components, as well as, entire application releases during all phases of the software development lifecycle.

Verify the SCM plan identifies and tracks all actions and changes resulting from a change request from initiation to release.

Verify the SCM plan contains procedures to identify, document, review, and authorize any change requests to the application.

Verify the SCM plan defines the responsibilities, the actions to be performed, the tools, techniques and methodologies, and defines an initial set of base-lined software components.

Verify the SCM plan objects have security classifications labels if processing classified data.

Verify the SCM plan identifies tools and version numbers used in the software development lifecycle.

Verify the SCM plan identifies mechanisms for controlled access of simultaneous individuals updating the same application component.

Verify the SCM plan assures only authorized changes by authorized persons are possible.

Verify the SCM plan identifies mechanisms to control access and audit changes between different versions of objects subject to configuration control.

Verify the SCM plan identifies mechanisms to track and audit all modifications of objects under configuration control. Audits will include the originator and date and time of the modification.

Ask the application representative to review the applications SCM plan.

The SCM plan should contain the following:

- Description of the configuration control and change management process
- Types of objects developed
- Roles and responsibilities of the organization
- Defined responsibilities
- Actions to be performed
- Tools used in the process
- Techniques and methodologies
- Initial set of baselined software components

If the SCM plan does not include the above, this is a finding.

The SCM plan should identify all objects that are under configuration management control. Ask the application representative to provide access to the CMR and to identify the objects shown in the SCM plan.

If the application representative cannot display all types of objects under CMR control, this is a finding.

The SCM plan should identify third-party tools and respective version numbers.

If the SCM plan does not identify third-party tools, this is a finding.

The SCM plan should identify mechanisms for controlled access of individuals simultaneously updating the same application component.

If the SCM plan does not identify mechanisms for controlled access, this is a finding.

The SCM plan assures only authorized changes by authorized persons are allowed.

If the SCM plan does not assure only authorized changes are made, this is a finding.

The SCM plan should identify the mechanisms used to control access and audit changes between different versions of objects subject to CMR control.

If the SCM plan does not identify mechanisms used to control access and to audit changes between different versions of objects subject to CMR control, this is a finding.

The SCM plan should have procedures for label versions of application components and application builds under configuration management control. Ask the application representative to demonstrate the CMR and ensure it contains versions and releases of the application. Ask the application representative to create a build or demonstrate a current release of the application that can be recreated.

If the application representative cannot display releases and application component versions, this is a finding.

The CMR should track change requests from beginning to end. Ask the application representative to display a completed or in-process change request.

If the CMR cannot track change requests, this is a finding.

If the application has just completed its first release, there may not be any change requests logged in the CMR.  In this case, this finding is not applicable.

The CMR should authorize change requests to the application. Ask the application representative to display an authorized change request and identify who is responsible for authorizing change requests.

If the CMR does not track authorized change requests, this is a finding.

If the application has just completed its first release, there may not be any change requests logged in the CMR. In this case, this finding is not applicable.

The CMR should contain security classification labels for code and documentation in the repository. 

Classification labels are not applicable to unclassified systems.  If the applications managed by the CMR are not classified, this requirement is not applicable.

If the CMR manages classified applications and there are no classification labels of code and documentation in the CMR, this is a finding.

The CMR should audit all objects under CM control for modification.

If the CMR does not audit for modifications, this is a finding.'
  desc 'fix', 'Create and update a SCM plan describing the configuration control and change management process of application objects developed by the organization and the roles and responsibilities of the organization.  Configure CMR to comply.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24302r493804_chk'
  tag severity: 'medium'
  tag gid: 'V-222632'
  tag rid: 'SV-222632r864416_rule'
  tag stig_id: 'APSC-DV-003010'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24291r493805_fix'
  tag 'documentable'
  tag legacy: ['SV-84965', 'V-70343']
  tag cci: ['CCI-001795']
  tag nist: ['CM-9 b']
end
