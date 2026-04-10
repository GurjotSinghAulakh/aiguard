import * as vscode from "vscode";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let debounceTimer: NodeJS.Timeout | undefined;

// Severity mapping from AIGuard → VS Code
const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  info: vscode.DiagnosticSeverity.Information,
};

interface AIGuardFinding {
  rule_id: string;
  rule_name: string;
  message: string;
  line: number;
  end_line: number | null;
  column: number;
  severity: string;
  confidence: number;
  suggestion: string | null;
}

interface AIGuardFileReport {
  file_path: string;
  findings: AIGuardFinding[];
}

interface AIGuardReport {
  score: number;
  total_findings: number;
  file_reports: AIGuardFileReport[];
}

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("aiguard");
  context.subscriptions.push(diagnosticCollection);

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100
  );
  statusBarItem.command = "aiguard.scan";
  context.subscriptions.push(statusBarItem);

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand("aiguard.scan", () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        scanDocument(editor.document);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("aiguard.scanWorkspace", async () => {
      const folders = vscode.workspace.workspaceFolders;
      if (!folders) {
        vscode.window.showWarningMessage("No workspace folder open.");
        return;
      }
      await scanPath(folders[0].uri.fsPath);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("aiguard.fix", async () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        await fixDocument(editor.document);
      }
    })
  );

  // Run on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration("aiguard");
      if (config.get<boolean>("enable") && config.get<boolean>("runOnSave")) {
        scanDocument(doc);
      }
    })
  );

  // Run on type (debounced)
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const config = vscode.workspace.getConfiguration("aiguard");
      if (config.get<boolean>("enable") && config.get<boolean>("runOnType")) {
        if (debounceTimer) {
          clearTimeout(debounceTimer);
        }
        debounceTimer = setTimeout(() => {
          scanDocument(event.document);
        }, 1500);
      }
    })
  );

  // Scan on open
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration("aiguard");
      if (config.get<boolean>("enable")) {
        scanDocument(doc);
      }
    })
  );

  // Scan already-open documents
  if (vscode.window.activeTextEditor) {
    const config = vscode.workspace.getConfiguration("aiguard");
    if (config.get<boolean>("enable")) {
      scanDocument(vscode.window.activeTextEditor.document);
    }
  }
}

async function scanDocument(document: vscode.TextDocument): Promise<void> {
  const supported = ["python", "markdown"];
  if (!supported.includes(document.languageId)) {
    return;
  }

  // Skip untitled (unsaved) documents
  if (document.uri.scheme !== "file") {
    return;
  }

  const filePath = document.uri.fsPath;
  await scanPath(filePath);
}

async function scanPath(targetPath: string): Promise<void> {
  const config = vscode.workspace.getConfiguration("aiguard");
  const executable = config.get<string>("executablePath") || "aiguard";
  const configPath = config.get<string>("configPath") || "";
  const failUnder = config.get<number>("failUnder") || 0;

  let cmd = `${executable} scan "${targetPath}" --format json`;
  if (configPath) {
    cmd += ` --config "${configPath}"`;
  }

  try {
    const { stdout } = await execAsync(cmd, {
      timeout: 30000,
      maxBuffer: 5 * 1024 * 1024,
    });

    const report: AIGuardReport = JSON.parse(stdout);
    applyDiagnostics(report);
    updateStatusBar(report.score, failUnder);
  } catch (err: unknown) {
    // AIGuard exits non-zero when score < threshold — still has valid output
    if (err && typeof err === "object" && "stdout" in err) {
      const stdout = (err as { stdout: string }).stdout;
      try {
        const report: AIGuardReport = JSON.parse(stdout);
        applyDiagnostics(report);
        updateStatusBar(report.score, failUnder);
        return;
      } catch {
        // Parse failed, fall through
      }
    }

    const message =
      err instanceof Error ? err.message : String(err);
    if (message.includes("ENOENT") || message.includes("not found")) {
      vscode.window.showErrorMessage(
        "AIGuard not found. Install with: pip install ai-guard-cli"
      );
    }
  }
}

function applyDiagnostics(report: AIGuardReport): void {
  // Clear all existing diagnostics
  diagnosticCollection.clear();

  const diagnosticMap = new Map<string, vscode.Diagnostic[]>();

  for (const fileReport of report.file_reports) {
    const diagnostics: vscode.Diagnostic[] = [];

    for (const finding of fileReport.findings) {
      const line = Math.max(0, finding.line - 1);
      const endLine = finding.end_line
        ? Math.max(0, finding.end_line - 1)
        : line;

      const range = new vscode.Range(
        new vscode.Position(line, finding.column),
        new vscode.Position(endLine, Number.MAX_SAFE_INTEGER)
      );

      const severity =
        SEVERITY_MAP[finding.severity] ??
        vscode.DiagnosticSeverity.Warning;

      const diagnostic = new vscode.Diagnostic(
        range,
        `[${finding.rule_id}] ${finding.message}`,
        severity
      );

      diagnostic.source = "AIGuard";
      diagnostic.code = finding.rule_id;

      if (finding.suggestion) {
        diagnostic.relatedInformation = [
          new vscode.DiagnosticRelatedInformation(
            new vscode.Location(
              vscode.Uri.file(fileReport.file_path),
              range
            ),
            `Suggestion: ${finding.suggestion}`
          ),
        ];
      }

      diagnostics.push(diagnostic);
    }

    diagnosticMap.set(fileReport.file_path, diagnostics);
  }

  for (const [filePath, diagnostics] of diagnosticMap) {
    diagnosticCollection.set(vscode.Uri.file(filePath), diagnostics);
  }
}

function updateStatusBar(score: number, failUnder: number): void {
  statusBarItem.text = `$(shield) AIGuard: ${score}/100`;

  if (score >= 80) {
    statusBarItem.backgroundColor = undefined;
    statusBarItem.tooltip = "AIGuard: Code looks great!";
  } else if (score >= failUnder) {
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.warningBackground"
    );
    statusBarItem.tooltip = "AIGuard: Some issues found";
  } else {
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.errorBackground"
    );
    statusBarItem.tooltip = `AIGuard: Score below threshold (${failUnder})`;
  }

  statusBarItem.show();
}

async function fixDocument(document: vscode.TextDocument): Promise<void> {
  const config = vscode.workspace.getConfiguration("aiguard");
  const executable = config.get<string>("executablePath") || "aiguard";

  const filePath = document.uri.fsPath;
  const cmd = `${executable} scan "${filePath}" --fix --format json`;

  try {
    await execAsync(cmd, { timeout: 30000 });
    vscode.window.showInformationMessage("AIGuard: Auto-fixes applied!");
    // Re-scan to update diagnostics
    await scanDocument(document);
  } catch {
    vscode.window.showWarningMessage(
      "AIGuard: Some fixes applied (scan reported remaining issues)."
    );
    await scanDocument(document);
  }
}

export function deactivate(): void {
  if (debounceTimer) {
    clearTimeout(debounceTimer);
  }
  diagnosticCollection.dispose();
  statusBarItem.dispose();
}
