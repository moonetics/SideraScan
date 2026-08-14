import type { Metadata } from "next";
import { LegalList, LegalPage, LegalSection } from "../legal-page";

export const metadata: Metadata = {
  title: "Terms and Conditions | SideraScan",
  description: "SideraScan terms and conditions.",
};

const effectiveDate = "14 August 2026";

export default function TermsPage() {
  return (
    <LegalPage
      description="These bilingual terms govern access to SideraScan dashboard, scanner, forensic review, automation, and AI-assisted review features. Bahasa Indonesia is the primary reference; English is provided for convenience."
      effectiveDate={effectiveDate}
      title="Terms and Conditions"
    >
      <LegalSection title="1. Penerimaan Ketentuan / Acceptance">
        <p>
          <strong>Bahasa Indonesia.</strong> Dengan mengakses dashboard,
          membuat scanner key, menjalankan scanner, mengunggah hasil scan, atau
          menggunakan fitur review SideraScan, Anda menyetujui Syarat dan
          Ketentuan ini.
        </p>
        <p>
          <strong>English.</strong> By accessing the dashboard, creating scanner
          keys, running the scanner, uploading scan results, or using SideraScan
          review features, you agree to these Terms and Conditions.
        </p>
      </LegalSection>

      <LegalSection title="2. Layanan / Service">
        <p>
          SideraScan provides consent-based scan session management, scanner key
          validation, forensic metadata collection, custom detection rules,
          dashboard review, monitoring, alerting, and optional advisory AI review
          through n8n.
        </p>
        <p>
          SideraScan is a review and investigation support tool. It is not a
          promise of cheat detection certainty, not a law-enforcement tool, and
          not an automated punishment system.
        </p>
      </LegalSection>

      <LegalSection title="3. Persetujuan Scan / Scan Consent">
        <LegalList
          items={[
            "A scan must only be started with the knowledge and consent of the person operating the device.",
            "The scanner key is account-scoped and may not be shared outside the intended scan flow.",
            "Starting a scan authorizes SideraScan to collect the metadata described in the Privacy Policy.",
            "Administrators must not use SideraScan for covert, forced, or unauthorized scanning.",
          ]}
        />
      </LegalSection>

      <LegalSection title="4. Akun dan Role / Accounts and Roles">
        <p>
          Dashboard users are responsible for safeguarding their credentials and
          using only the permissions assigned to them. Super Admins, Account
          Owners, Moderators, and Viewers must follow the role boundaries shown
          in the product.
        </p>
      </LegalSection>

      <LegalSection title="5. Keputusan Moderasi / Moderation Decisions">
        <LegalList
          items={[
            "AI Review is advisory only and cannot auto-ban, auto-punish, or create final enforcement actions.",
            "Bans, account restrictions, HWID/device marks, and dispute outcomes must remain manual decisions by authorized staff.",
            "Moderators should consider false positives, historical artifacts, player explanation, and corroborating evidence before taking action.",
            "SideraScan findings are signals for review, not absolute proof by themselves.",
          ]}
        />
      </LegalSection>

      <LegalSection title="6. Larangan / Prohibited Use">
        <LegalList
          items={[
            "Using SideraScan to scan a device without consent.",
            "Attempting to steal, brute-force, leak, or reuse scanner keys, upload tokens, dashboard sessions, or webhook secrets.",
            "Reverse engineering, tampering with, or redistributing the scanner except where expressly permitted by the operator.",
            "Uploading fabricated scan data, misleading evidence, malware, or data from a device you are not authorized to scan.",
            "Using the dashboard to expose private data, harass users, or make automated punishment decisions.",
          ]}
        />
      </LegalSection>

      <LegalSection title="7. Custom Detections and Intelligence">
        <p>
          Custom detections, string rules, and executor intelligence feeds are
          configurable review tools. Managed intelligence matches are advisory by
          default. Name-only matches should not be treated as proof of cheating
          without supporting signals such as suspicious path, unsigned binary,
          Roblox correlation, persistence, Defender changes, or execution chain.
        </p>
      </LegalSection>

      <LegalSection title="8. n8n, AI, and Notifications">
        <p>
          SideraScan may use self-hosted n8n workflows to process
          `scan.completed` and `security.alert` events. These workflows should
          receive redacted backend-generated payloads only. AI providers and
          notification sinks such as Discord are optional integrations and must
          be configured securely by the operator.
        </p>
      </LegalSection>

      <LegalSection title="9. Availability and Changes">
        <p>
          SideraScan may be changed, updated, interrupted, or discontinued.
          Scanner versions may be blocked when outdated or unsafe. Features such
          as AI review, alert delivery, executor intelligence feeds, and forensic
          collectors may be unavailable, rate-limited, or best-effort.
        </p>
      </LegalSection>

      <LegalSection title="10. Data and Privacy">
        <p>
          Use of SideraScan is also governed by the Privacy Policy. If you do
          not agree with the collection and processing described there, do not
          start a scan or use the dashboard.
        </p>
      </LegalSection>

      <LegalSection title="11. No Warranty">
        <p>
          SideraScan is provided on an “as is” and “as available” basis to the
          extent permitted by applicable law. The operator does not guarantee
          that every cheat, exploit, suspicious artifact, false positive, system
          state, or network issue will be detected or correctly classified.
        </p>
      </LegalSection>

      <LegalSection title="12. Limitation of Liability">
        <p>
          To the extent permitted by Indonesian law, the operator is not liable
          for indirect, incidental, consequential, special, punitive, or
          reputational damages arising from use of SideraScan. Authorized staff
          remain responsible for moderation decisions and for complying with
          applicable community, contractual, and legal obligations.
        </p>
      </LegalSection>

      <LegalSection title="13. Indemnity">
        <p>
          You agree to be responsible for claims, losses, liabilities, costs, or
          expenses arising from your misuse of SideraScan, unauthorized scanning,
          violation of these Terms, or violation of applicable law or third-party
          rights.
        </p>
      </LegalSection>

      <LegalSection title="14. Hukum yang Berlaku / Governing Law">
        <p>
          <strong>Bahasa Indonesia.</strong> Ketentuan ini diatur oleh hukum
          Republik Indonesia. Sengketa sebaiknya diselesaikan terlebih dahulu
          melalui musyawarah. Jika tidak tercapai penyelesaian, forum penyelesaian
          sengketa mengikuti domisili hukum operator SideraScan atau forum lain
          yang ditentukan dalam perjanjian tertulis dengan pelanggan.
        </p>
        <p>
          <strong>English.</strong> These Terms are governed by the laws of the
          Republic of Indonesia. Disputes should first be resolved in good faith.
          If no settlement is reached, the dispute forum follows the legal
          domicile of the SideraScan operator or another forum specified in a
          written agreement with the customer.
        </p>
      </LegalSection>

      <LegalSection title="15. Perubahan / Changes">
        <p>
          We may update these Terms when the product, security model, legal
          requirements, or business structure changes. Material updates should be
          published with a new effective date.
        </p>
      </LegalSection>

      <LegalSection title="16. Contact">
        <p>
          Questions about these Terms should be sent through the official contact
          channel provided by the SideraScan operator. Production contact details
          should be added before public launch.
        </p>
      </LegalSection>

      <LegalSection title="Important Notice">
        <p>
          These Terms are a product-ready draft for an Indonesia-based project.
          They should be reviewed by qualified Indonesian counsel before public
          commercial deployment.
        </p>
      </LegalSection>
    </LegalPage>
  );
}
