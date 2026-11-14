-- Rapports au format PDF.
ALTER TABLE reports DROP CONSTRAINT reports_format_check;
ALTER TABLE reports ADD CONSTRAINT reports_format_check CHECK (format IN ('html', 'json', 'pdf'));
