import type { Metadata } from "next";
import { LegalList, LegalPage, LegalSection } from "../legal-page";

export const metadata: Metadata = {
  title: "Privacy Policy | SideraScan",
  description: "SideraScan privacy policy and personal data protection notice.",
};

const effectiveDate = "14 August 2026";

export default function PrivacyPolicyPage() {
  return (
    <LegalPage
      description="This bilingual notice explains how SideraScan processes dashboard, scanner, forensic, security, and AI review metadata. Bahasa Indonesia is the primary reference; English is provided for convenience."
      effectiveDate={effectiveDate}
      title="Privacy Policy"
    >
      <LegalSection title="1. Ringkasan / Summary">
        <p>
          <strong>Bahasa Indonesia.</strong> SideraScan adalah sistem review scan
          berbasis persetujuan untuk membantu administrator dan moderator
          meninjau metadata keamanan. SideraScan tidak dirancang untuk mengambil
          password lokal, cookies browser, clipboard, screenshot, isi file
          pribadi, raw HWID, MachineGuid mentah, atau serial hardware mentah.
        </p>
        <p>
          <strong>English.</strong> SideraScan is a consent-based scan review
          system that helps administrators and moderators review security
          metadata. SideraScan is not designed to collect local passwords,
          browser cookies, clipboard data, screenshots, private file contents,
          raw HWID, raw MachineGuid, or raw hardware serial numbers.
        </p>
      </LegalSection>

      <LegalSection title="2. Pengendali Data / Data Controller">
        <p>
          <strong>Bahasa Indonesia.</strong> Layanan ini dioperasikan sebagai
          proyek SideraScan by SideraLabs, developed by Squad Limpul. Jika entitas
          hukum formal sudah dibentuk, identitas dan alamat resmi entitas tersebut
          akan menggantikan informasi ini.
        </p>
        <p>
          <strong>English.</strong> This service is operated as SideraScan by
          SideraLabs, developed by Squad Limpul. If a formal legal entity is
          established, the entity identity and registered address will replace
          this notice.
        </p>
      </LegalSection>

      <LegalSection title="3. Data yang Kami Proses / Data We Process">
        <LegalList
          items={[
            "Dashboard account data: display name, email, username, role, account membership, status, login/session metadata.",
            "Scanner session data: scanner key validation status, scan session ID, scanner version, platform, architecture, timestamps, upload status, and technical telemetry.",
            "Scan result metadata: OS/system summary, masked paths, process metadata, module status, forensic metadata, findings, evidence references, hashes, and device fingerprint hash.",
            "Device/HWID review data: fingerprint hash, fingerprint prefix, confidence, device mark status, and manual reviewer notes.",
            "Security/audit data: audit logs, security events, monitoring events, alert history, role changes, scanner key operations, rule changes, and retry events.",
            "AI/n8n review data: redacted scan summaries sent to self-hosted n8n and configured AI provider for advisory review only.",
          ]}
        />
      </LegalSection>

      <LegalSection title="4. Data yang Tidak Kami Kumpulkan / Data We Do Not Collect">
        <LegalList
          items={[
            "Local computer passwords, browser passwords, browser cookies, or clipboard contents.",
            "Screenshots, webcam, microphone, keystrokes, memory dumps, packet captures, or private file contents.",
            "Raw MachineGuid, raw hardware serial numbers, raw full HWID, raw scanner key, upload token, or nonce in nested reports/logs.",
            "Browser full history or private chat content from Discord, Telegram, or similar apps.",
            "Executor binaries or third-party executable downloads from intelligence feeds.",
          ]}
        />
      </LegalSection>

      <LegalSection title="5. Tujuan Pemrosesan / Purposes">
        <LegalList
          items={[
            "Validate scanner keys and create scan sessions.",
            "Display scan results, forensic metadata, and review findings to authorized dashboard users.",
            "Support account-scoped moderation, auditability, and security investigation workflows.",
            "Run custom detections and managed intelligence rules without rebuilding the scanner.",
            "Provide advisory AI review through n8n when enabled; AI review never performs auto-ban or final punishment actions.",
            "Maintain security monitoring, alerting, troubleshooting, abuse prevention, and backup/restore operations.",
          ]}
        />
      </LegalSection>

      <LegalSection title="6. Dasar Pemrosesan / Legal Basis">
        <p>
          <strong>Bahasa Indonesia.</strong> Pemrosesan data dilakukan berdasarkan
          persetujuan pengguna untuk memulai scan, pelaksanaan layanan yang
          diminta oleh account/admin, kepentingan keamanan yang sah, pemenuhan
          kewajiban audit internal, dan dasar lain yang diizinkan oleh hukum
          Indonesia, termasuk UU No. 27 Tahun 2022 tentang Pelindungan Data
          Pribadi dan ketentuan sistem elektronik yang berlaku.
        </p>
        <p>
          <strong>English.</strong> Data is processed based on scan consent,
          delivery of requested services for the relevant account/admin,
          legitimate security interests, internal audit needs, and other lawful
          grounds permitted by Indonesian law, including Law No. 27 of 2022 on
          Personal Data Protection and applicable electronic system regulations.
        </p>
      </LegalSection>

      <LegalSection title="7. Berbagi Data / Data Sharing">
        <p>
          SideraScan may share limited redacted metadata with service components
          needed to operate the system, such as the self-hosted n8n instance, the
          configured AI provider, and optional alert channels such as Discord.
          Scanner raw operational secrets, raw hardware identifiers, private file
          contents, and unmasked private paths must not be sent to these
          integrations.
        </p>
      </LegalSection>

      <LegalSection title="8. Retensi / Retention">
        <p>
          Data is retained according to the retention settings configured by the
          Super Admin. The default product policy may include shorter retention
          for screenshots or samples if such features are ever enabled, moderate
          retention for scan results and monitoring data, and longer retention
          for audit logs. Retention dry-runs may be used before deletion.
        </p>
      </LegalSection>

      <LegalSection title="9. Keamanan / Security">
        <LegalList
          items={[
            "Scanner keys, upload tokens, nonce values, passwords, and raw identifiers are redacted from logs and reports.",
            "Temporary scanner retry payloads are protected with Windows user encryption when available.",
            "n8n webhooks use HMAC signatures, timestamps, and idempotency keys.",
            "Dashboard access is role-based and account-scoped.",
            "Sensitive administrative actions are audited.",
          ]}
        />
      </LegalSection>

      <LegalSection title="10. Hak Subjek Data / Data Subject Rights">
        <p>
          Subject to applicable Indonesian law, you may request access,
          correction, deletion, restriction, or clarification regarding personal
          data processed by SideraScan. Because scan records may be tied to audit,
          security, dispute, or anti-abuse workflows, some requests may require
          verification and may be limited where retention is legally or
          operationally necessary.
        </p>
      </LegalSection>

      <LegalSection title="11. Transfer dan Lokasi / Transfer and Location">
        <p>
          Local development may run on local machines and Docker services.
          Production deployment should use secured infrastructure, HTTPS, private
          databases, and controlled access. If third-party AI or notification
          providers are used, redacted metadata may be processed by those
          providers according to their own terms.
        </p>
      </LegalSection>

      <LegalSection title="12. Perubahan / Changes">
        <p>
          We may update this policy when the product, legal requirements, or
          security model changes. Material changes should be published on this
          page with a new effective date.
        </p>
      </LegalSection>

      <LegalSection title="13. Kontak / Contact">
        <p>
          For privacy requests, use the official contact channel provided by the
          SideraScan operator or the account administrator responsible for your
          scan. Production contact details should be added before public launch.
        </p>
      </LegalSection>

      <LegalSection title="Important Notice">
        <p>
          This policy is a product-ready draft prepared for an Indonesia-based
          project. It should be reviewed by qualified Indonesian counsel before
          public commercial deployment.
        </p>
      </LegalSection>
    </LegalPage>
  );
}
