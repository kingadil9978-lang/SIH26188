import "./globals.css";

export const metadata = {
  title: "VERUS | AI Identity & Document Screening",
  description:
    "OCR, document validation, tamper screening, face verification and risk scoring for identity and travel documents.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
