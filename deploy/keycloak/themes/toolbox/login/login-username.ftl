<#-- The realm flow enforces upstream-only authentication independently of this
     presentation. Never use hiding a form as an authentication control. -->
<#import "template.ftl" as layout>
<#import "social-providers.ftl" as identityProviders>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header">
        ${msg("loginAccountTitle")}
    <#elseif section = "socialProviders">
        <#if social.providers?? && social.providers?has_content>
            <@identityProviders.show social=social />
        </#if>
    </#if>
</@layout.registrationLayout>
