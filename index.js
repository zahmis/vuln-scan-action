const core = require('@actions/core');
const github = require('@actions/github');
const axios = require('axios');
const fs = require('node:fs');
const path = require('node:path');
const { execSync } = require('node:child_process');
const os = require('node:os');
const { GoogleGenerativeAI } = require("@google/generative-ai");

// Perplexity APIのエンドポイント
const PERPLEXITY_API_ENDPOINT = 'https://api.perplexity.ai/chat/completions';
const TEMP_DIR_PREFIX = 'dep-clone-';

// --- GitHub Interaction ---

async function getDiffContent(octokit, owner, repo, pullNumber) {
  try {
    const response = await octokit.rest.pulls.get({
      owner,
      repo,
      pull_number: pullNumber,
      mediaType: {
        format: 'diff'
      }
    });
    console.log('PR Diff content successfully retrieved.');
    return response.data;
  } catch (error) {
    console.error(`Failed to get diff content: ${error.message}`);
    throw new Error(`差分の取得に失敗しました: ${error.message}`);
  }
}

async function postComment(octokit, owner, repo, issueNumber, body) {
    const MAX_COMMENT_LENGTH = 65536; // GitHub comment length limit
    let commentBody = body;

    if (commentBody.length > MAX_COMMENT_LENGTH) {
        console.warn(`Generated report exceeds GitHub comment length limit (${commentBody.length}/${MAX_COMMENT_LENGTH}). Truncating...`);
        const truncationMessage = "\n\n**Note:** レポートが長すぎるため、一部省略されました。";
        commentBody = commentBody.substring(0, MAX_COMMENT_LENGTH - truncationMessage.length) + truncationMessage;
    }

    try {
        console.log(`Posting comment to PR #${issueNumber}...`);
        await octokit.rest.issues.createComment({
          owner,
          repo,
          issue_number: issueNumber,
          body: commentBody
        });
        console.log('Comment posted successfully.');
    } catch (error) {
        console.error(`Failed to post comment: ${error.message}`);
        // Optionally re-throw or handle specific errors (like 403 permission errors)
        // Consider just logging the error and letting the action continue?
    }
}


// --- API Calls ---

async function analyzeDependencies(diff) {
  const apiKey = core.getInput('perplexity-api-key');
  if (!apiKey) {
    console.warn('Perplexity API key not provided. Skipping dependency analysis.');
    return { dependencies: [], overall_assessment: { recommendation_jp: '判断不可', reasoning_jp: 'APIキー未設定のため分析スキップ' } };
  }

  console.log('Starting dependency analysis with Perplexity...');
  try {
    const response = await axios.post(PERPLEXITY_API_ENDPOINT, {
      model: "sonar-pro", // Or another suitable model
      messages: [
        {
          role: "system",
          content: `
あなたはコードの依存関係変更を分析するセキュリティ専門家です。提供された差分情報を基に、各依存関係の変更（追加、更新、削除）を特定してください。

**更新**された依存関係については、以下の情報を日本語で詳しく分析・評価してください：
1.  **現状バージョン (From) の主なセキュリティリスク:** 現在使用しているバージョンに存在する既知の脆弱性や懸念点を具体的に記述してください。無い場合は「特筆すべき既知のリスクなし」としてください。
2.  **更新後バージョン (To) の評価:**
    *   **改善点:** この更新によって解消される主要な脆弱性や問題点を記述してください。
    *   **潜在的リスク:** 更新後のバージョンで新たに懸念される点（例：既知の脆弱性、大きなAPI変更による互換性問題など）があれば記述してください。無い場合は「特筆すべき潜在的リスクなし」としてください。
3.  **アップグレード判断と理由:** 上記を踏まえ、アップグレードを「強く推奨」「推奨」「検討」「不要」のいずれかで判断し、**その明確な理由**を簡潔に記述してください。（例：「深刻な脆弱性解消のため強く推奨」「互換性リスクを考慮し要検討」など）

**追加**された依存関係については、以下の情報を日本語で分析・評価してください：
1.  **依存関係の概要と用途:** このライブラリが何をするものか、一般的な用途を簡潔に説明してください。
2.  **既知のセキュリティリスク:** 追加されるバージョンに既知の脆弱性や一般的なセキュリティ上の懸念（例：メンテナンス状況、過去の脆弱性傾向など）があれば記述してください。無い場合は「特筆すべき既知のリスクなし」としてください。
3.  **導入判断:** 「導入可」「注意して導入」「導入非推奨」のいずれかで判断し、その理由を簡潔に記述してください。

**削除**された依存関係については、削除による影響（もしあれば）を簡単に記述してください。

**全体評価:**
*   **総合的なマージ判断 (Japanese):** 全ての変更を考慮し、「マージ可」「注意してマージ」「マージ前に対応必須」のいずれかで判断してください。
*   **判断理由 (Japanese):** 総合的な判断の根拠となる主要な理由を簡潔に記述してください。

**応答形式:**
以下のJSON構造に従って、**JSONオブジェクトのみ**を応答してください。Markdownフォーマットや他のテキストは含めないでください。

\`\`\`json
{
  "dependencies": [
    {
      "name": "string",
      "change_type": "updated",
      "version_change": { "from": "string", "to": "string" },
      "current_version_risks_jp": "string",
      "new_version_assessment_jp": {
        "improvements_jp": "string",
        "potential_risks_jp": "string"
      },
      "upgrade_recommendation_jp": "強く推奨|推奨|検討|不要",
      "upgrade_reasoning_jp": "string"
    },
    {
      "name": "string",
      "change_type": "added",
      "added_version": "string",
      "description_jp": "string",
      "known_risks_jp": "string",
      "adoption_recommendation_jp": "導入可|注意して導入|導入非推奨",
      "adoption_reasoning_jp": "string"
    },
    {
      "name": "string",
      "change_type": "removed",
      "removal_impact_jp": "string"
    }
    // ... more dependencies
  ],
  "overall_assessment": {
    "recommendation_jp": "マージ可|注意してマージ|マージ前に対応必須",
    "reasoning_jp": "string"
  }
}
\`\`\`
`
        },
        {
          role: "user",
          content: `以下の差分情報について、依存関係の変更を分析してください:\n\n\`\`\`diff\n${diff}\n\`\`\``
        }
      ]
    }, {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      timeout: 180000 // 3 minute timeout
    });

    let content = response.data.choices[0].message.content;
    content = content.replace(/^```json\s*\n|\n```\s*$/g, '').trim();
    const analysisResult = JSON.parse(content);

    // Basic validation of the response structure
    if (!analysisResult || typeof analysisResult !== 'object' || !analysisResult.dependencies || !Array.isArray(analysisResult.dependencies) || !analysisResult.overall_assessment) {
      console.error('Invalid JSON structure received from dependency analysis API:', content);
      throw new Error('依存関係分析APIからの応答形式が無効です。');
    }

    console.log('Dependency analysis completed successfully.');
    // Log the raw result for debugging if needed (optional)
    // console.log('Raw Dependency Analysis Result:', JSON.stringify(analysisResult, null, 2));
    return analysisResult;

  } catch (error) {
    console.error(`Error during dependency analysis: ${error.message}`);
    if (error.response) {
      console.error('API Error Response:', error.response.data);
    } else if (error.request) {
      console.error('API No Response Received');
    }
    // Return a default structure indicating failure
    return {
      dependencies: [],
      overall_assessment: { recommendation_jp: '判断不可', reasoning_jp: `依存関係分析中にエラーが発生しました: ${error.message}` }
    };
  }
}

async function analyzeVulnerabilities(diff, dependencies) {
  const apiKey = core.getInput('perplexity-api-key');
   if (!apiKey) {
    console.warn('Perplexity API key not provided. Skipping vulnerability analysis.');
    return { vulnerabilities: [] };
  }

  // Only include dependency names and versions for context
  const depContext = dependencies.map(d => ({ name: d.name, from: d.version_change?.from, to: d.version_change?.to || d.added_version }));

  console.log('Starting vulnerability analysis with Perplexity...');
  try {
    const response = await axios.post(PERPLEXITY_API_ENDPOINT, {
      model: "sonar-pro", // Or another suitable model
      messages: [
        {
          role: "system",
          content: `
あなたはコードと依存関係の変更を分析するセキュリティ専門家です。提供されたコード差分と依存関係の変更リストを基に、潜在的なセキュリティ脆弱性や懸念事項を特定してください。OWASP Top 10などの一般的な脆弱性パターンに注意してください。

各脆弱性や懸念事項について、以下の情報を日本語で記述してください：
1.  **脆弱性/懸念事項の名称:** 例：「SQLインジェクションの可能性」「不適切なエラー処理」など。
2.  **説明:** 具体的にどのような問題か、どのような影響があるかを説明してください。
3.  **変更影響:** この問題は、今回のコード/依存関係の変更によって「**導入された**」ものですか、「**解消された**」ものですか、それとも「**変更前から存在し解消されていない**」ものですか？ (\`introduced\` | \`resolved\` | \`persistent\` のいずれかを指定)
4.  **関連箇所:** 問題が存在するコード箇所（ファイル名、行番号など）、または関連する依存関係名を特定してください。
5.  **推奨される対策:** 具体的な修正方法や、取るべきアクションを提案してください。
6.  **重要度:** リスクの度合いを「重大(Critical)」「高(High)」「中(Medium)」「低(Low)」で評価してください。

**応答形式:**
以下のJSON構造に従って、**JSONオブジェクトのみ**を応答してください。Markdownフォーマットや他のテキストは含めないでください。脆弱性が見つからない場合は、空の配列 \`[]\` を含むJSONを返してください。

\`\`\`json
{
  "vulnerabilities": [
    {
      "name_jp": "string",
      "description_jp": "string",
      "change_impact": "introduced | resolved | persistent",
      "location": "string (e.g., file.go:123 or dependency_name)",
      "recommendation_jp": "string",
      "severity": "Critical | High | Medium | Low"
    }
    // ... more vulnerabilities
  ]
}
\`\`\`
`
        },
        {
          role: "user",
          content: `以下のコード差分と依存関係の変更を分析し、脆弱性や懸念事項を報告してください。

コード差分:
\`\`\`diff
${diff}
\`\`\`

依存関係の変更 (概要):
\`\`\`json
${JSON.stringify(depContext, null, 2)}
\`\`\`
`
        }
      ]
    }, {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      timeout: 180000 // 3 minute timeout
    });

    let content = response.data.choices[0].message.content;
    content = content.replace(/^```json\s*\n|\n```\s*$/g, '').trim();
    const analysisResult = JSON.parse(content);

    // Basic validation
    if (!analysisResult || !Array.isArray(analysisResult.vulnerabilities)) {
        console.error('Invalid JSON structure received from vulnerability analysis API:', content);
        throw new Error('脆弱性分析APIからの応答形式が無効です。');
    }

    console.log('Vulnerability analysis completed successfully.');
    // console.log('Raw Vulnerability Analysis Result:', JSON.stringify(analysisResult, null, 2));
    return analysisResult;

  } catch (error) {
    console.error(`Error during vulnerability analysis: ${error.message}`);
     if (error.response) {
      console.error('API Error Response:', error.response.data);
    } else if (error.request) {
      console.error('API No Response Received');
    }
    return { vulnerabilities: [] }; // Return empty array on error
  }
}

async function analyzeCodeDiffWithGemini(codeDiff, dependencyName, versionFrom, versionTo) {
  const apiKey = core.getInput('gemini-api-key');
  if (!apiKey) {
    console.log(`Gemini API key not provided. Skipping code diff analysis for ${dependencyName}.`);
    return 'Gemini APIキー未設定のためスキップ';
  }
  if (!codeDiff || codeDiff.trim() === '') {
    console.log(`Code diff for ${dependencyName} is empty. Skipping Gemini analysis.`);
    return 'コード差分が空のためスキップ';
  }

  const MAX_DIFF_LENGTH = 1000000;
  if (codeDiff.length > MAX_DIFF_LENGTH) {
      console.warn(`Code diff for ${dependencyName} is too large (${codeDiff.length} chars). Skipping Gemini analysis.`);
      return `コード差分長すぎ (${codeDiff.length}文字) のためスキップ`;
  }

  console.log(`Analyzing code diff for ${dependencyName} (${versionFrom} -> ${versionTo}) with Gemini...`);
  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-pro-preview-03-25"}); // Use the latest appropriate model

    const generationConfig = {
      temperature: 0.3, // Increased temperature slightly
      maxOutputTokens: 2048,
      responseMimeType: "text/plain",
    };

    const chatSession = model.startChat({ generationConfig });

    // Updated prompt focusing on the 'what' and 'security impact', and adding instruction to avoid empty response
    const prompt = `
あなたは提出されたコード差分をレビューするセキュリティエンジニアです。以下の ${dependencyName} ライブラリのバージョン ${versionFrom} から ${versionTo} へのコード差分について、静的解析の観点からレビューしてください。

コード差分:
\`\`\`diff
${codeDiff}
\`\`\`

以下の点を日本語で具体的に報告してください：
1.  **主な変更内容:** この差分は、どのような機能変更、バグ修正、リファクタリング等を行っていますか？ 主要な変更点を簡潔に説明してください。
2.  **セキュリティへの影響:**
    *   **改善点:** この変更によって、セキュリティが向上する点（脆弱性の修正、堅牢性の向上など）はありますか？ 具体的に記述してください。
    *   **潜在的なリスク/懸念:** この変更によって、新たなセキュリティリスクや注意すべき点（例: 新しい依存性の導入、複雑性の増加、検証漏れの可能性）はありますか？ 具体的に記述してください。
    *   **総合評価:** 変更内容と影響を踏まえ、この差分に対するセキュリティ観点での総合的な評価（例：「明確な改善」「軽微な改善」「影響なし」「要注意」など）を記述してください。

脆弱性が見つからない、またはセキュリティへの影響が特にない場合は、その旨を明確に記述してください。単に「問題なし」とするのではなく、「特定の改善点が確認された」「特筆すべきセキュリティリスクは見当たらない」のように具体的に記述することが望ましいです。
**注意:** 必ず何らかの分析結果（変更内容の概要、影響評価、または「特筆すべき点なし」という結論のいずれか）を応答に含めてください。応答が空にならないようにしてください。
`;

    const result = await chatSession.sendMessage(prompt);
    const analysisText = result.response.text();
    console.log(`Gemini analysis complete for ${dependencyName}.`);
    return analysisText.trim() || 'Geminiからの応答が空でした。';

  } catch (error) {
    console.error(`Error analyzing code diff for ${dependencyName} with Gemini: ${error.message}`);
    if (error.response?.data) {
        console.error('Gemini API Error Data:', JSON.stringify(error.response.data));
    }
    return `Gemini APIでの分析中にエラー発生: ${error.message}`;
  }
}


// --- Git Operations ---

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), TEMP_DIR_PREFIX));
}

function cleanupTempDir(dirPath) {
  if (dirPath && fs.existsSync(dirPath)) {
    fs.rmSync(dirPath, { recursive: true, force: true });
    console.log(`Cleaned up temporary directory: ${dirPath}`);
  }
}

async function getDependencyCodeDiff(dependencyName, versionFrom, versionTo) {
  if (!versionFrom || !versionTo) {
      console.warn(`Skipping code diff for ${dependencyName}: Missing 'from' or 'to' version.`);
      return null;
  }
  let tempDir = null;
  try {
    // Corrected URL Parsing Logic
    let repoPath = dependencyName;
    const githubPrefix = 'github.com/';
    if (repoPath.startsWith(githubPrefix)) {
      repoPath = repoPath.substring(githubPrefix.length);
    }
    const versionSuffixMatch = repoPath.match(/\/v(\d+)$/);
    let repoNameOnly = repoPath; // Store the name without version suffix for logging
    if (versionSuffixMatch) {
      repoNameOnly = repoPath.substring(0, repoPath.length - versionSuffixMatch[0].length);
      repoPath = repoNameOnly; // Use the path without suffix for URL
    }
    // End of Corrected Logic

    const repoUrl = `https://github.com/${repoPath}.git`;
    console.log(`Constructed repo URL: ${repoUrl}`);

    tempDir = createTempDir();
    console.log(`Cloning ${repoNameOnly} (branch: ${versionTo}) into ${tempDir}...`);

    // Clone the target version first
    execSync(`git clone --quiet --depth 1 --branch ${versionTo} ${repoUrl} .`, { cwd: tempDir, stdio: 'pipe', encoding: 'utf8', timeout: 480000 });
    console.log(`Clone complete for branch ${versionTo}.`);

    // Fetch the specific tag/ref for the 'from' version
    console.log(`Fetching tag ${versionFrom}...`);
    // Use a try-catch specifically for fetch as tags might not always exist perfectly
    try {
        execSync(`git fetch --quiet origin refs/tags/${versionFrom}:refs/tags/${versionFrom} --depth 1 --no-tags`, { cwd: tempDir, stdio: 'pipe', encoding: 'utf8', timeout: 300000 });
        console.log(`Fetch complete for tag ${versionFrom}.`);
    } catch (fetchError) {
        console.warn(`Failed to fetch exact tag ref 'refs/tags/${versionFrom}'. Trying fetch by tag name only...`);
        console.warn(`Fetch error details: ${fetchError.message}`);
        // Fallback: try fetching just the tag name. Might fetch more history but could work.
        execSync(`git fetch --quiet origin tag ${versionFrom} --depth 1 --no-tags`, { cwd: tempDir, stdio: 'pipe', encoding: 'utf8', timeout: 300000 });
        console.log(`Fallback fetch potentially completed for tag ${versionFrom}.`);
    }

    // Verify the tag exists locally before diffing
    console.log('Verifying local tags...');
    const tagsOutput = execSync('git tag -l', { cwd: tempDir, encoding: 'utf8' });
    if (!tagsOutput.split('\n').includes(versionFrom)) {
        console.error(`Tag ${versionFrom} still not found locally after fetch attempts for ${repoNameOnly}. Cannot calculate diff.`);
        cleanupTempDir(tempDir);
        return null; // Cannot proceed without the tag
    }
     console.log(`Tag ${versionFrom} confirmed locally.`);

    console.log(`Calculating diff between tags/${versionFrom} and HEAD (${versionTo}) for ${repoNameOnly}...`);
    const diffOutput = execSync(`git diff tags/${versionFrom} HEAD`, { cwd: tempDir, encoding: 'utf8', maxBuffer: 75 * 1024 * 1024, timeout: 300000 });
    console.log(`Diff calculation successful. Diff length: ${diffOutput.length}`);

    cleanupTempDir(tempDir);
    return diffOutput;

  } catch (error) {
    console.error(`Error during getDependencyCodeDiff for ${dependencyName} (${versionFrom}..${versionTo}): ${error.message}`);
    if (error.stdout) console.error(`stdout:\n${error.stdout.toString().slice(0, 500)}...`);
    if (error.stderr) console.error(`stderr:\n${error.stderr.toString().slice(0, 500)}...`);
    if (error.status !== null) console.error(`Command exited with status ${error.status}`);
    cleanupTempDir(tempDir);
    return null;
  }
}


// --- Report Generation ---

// Helper to get severity score (higher number is more severe)
function getSeverityScore(severity) {
    const lowerSeverity = severity?.toLowerCase();
    switch(lowerSeverity) {
        case 'critical': return 4;
        case 'high': return 3;
        case 'medium': return 2;
        case 'low': return 1;
        default: return 0;
    }
}


function generateSecurityReport(dependencyAnalysis, vulnerabilityResults, codeDiffAnalyses) {
  let report = '## セキュリティ分析レポート\n\n';

  // --- 1. Overall Assessment ---
  const overall = dependencyAnalysis.overall_assessment;
  report += `**総合評価:** ${overall.recommendation_jp || '判断不可'}\n`;
  report += `**理由:** ${overall.reasoning_jp || 'N/A'}\n\n`;
  report += '---\n\n';

  // --- 2. Dependency Changes ---
  report += '## 依存関係の変更詳細\n\n';
  if (!dependencyAnalysis.dependencies || dependencyAnalysis.dependencies.length === 0) {
    report += '分析対象の依存関係の変更はありませんでした。\n';
  } else {
    for (const dep of dependencyAnalysis.dependencies) {
      report += `### ${dep.name}\n`;

      if (dep.change_type === 'updated') {
        report += `*   **変更:** バージョンアップ (\`${dep.version_change?.from}\` → \`${dep.version_change?.to}\`)\n`;
        report += `*   **現状 (${dep.version_change?.from}) のリスク:** ${dep.current_version_risks_jp || '情報なし'}\n`;
        if (dep.new_version_assessment_jp) {
            report += `*   **更新後 (${dep.version_change?.to}) の評価:**\n`;
            report += `    *   改善点: ${dep.new_version_assessment_jp.improvements_jp || '特になし'}\n`;
            report += `    *   潜在的リスク: ${dep.new_version_assessment_jp.potential_risks_jp || '特になし'}\n`;
        }
        report += `*   **アップグレード判断:** ${dep.upgrade_recommendation_jp || '判断不可'} - **理由:** ${dep.upgrade_reasoning_jp || 'N/A'}\n`;
        // Code Diff Analysis
        if (codeDiffAnalyses?.[dep.name]) {
            report += `*   **コード差分分析 (Gemini):**\n\`\`\`\n${codeDiffAnalyses[dep.name]}\n\`\`\`\n`;
        } else {
            report += `*   **コード差分分析 (Gemini):** スキップまたは失敗\n`;
        }

      } else if (dep.change_type === 'added') {
        report += `*   **変更:** 追加 (\`${dep.added_version}\`)\n`;
        report += `*   **概要:** ${dep.description_jp || '情報なし'}\n`;
        report += `*   **既知のリスク:** ${dep.known_risks_jp || '情報なし'}\n`;
        report += `*   **導入判断:** ${dep.adoption_recommendation_jp || '判断不可'} - **理由:** ${dep.adoption_reasoning_jp || 'N/A'}\n`;

      } else if (dep.change_type === 'removed') {
        report += `*   **変更:** 削除\n`;
        report += `*   **影響:** ${dep.removal_impact_jp || '影響の情報なし'}\n`;
      }
      report += '\n'; // Add space between dependencies
    }
  }
  report += '---\n\n';

  // --- 3. Vulnerabilities Found ---
  report += '## 検出された脆弱性・懸念事項\n\n';
  if (!vulnerabilityResults.vulnerabilities || vulnerabilityResults.vulnerabilities.length === 0) {
    report += '今回の変更に関連する新たな脆弱性や懸念事項は検出されませんでした。\n';
  } else {
    for (const vuln of vulnerabilityResults.vulnerabilities) {
      report += `### ${vuln.name_jp || '名称不明の問題'}\n`;
      report += `*   **重要度:** ${vuln.severity || '不明'}\n`;
      report += `*   **変更影響:** ${vuln.change_impact || '不明'}\n`; // introduced, resolved, persistent
      report += `*   **関連箇所:** ${vuln.location || '不明'}\n`;
      report += `*   **説明:** ${vuln.description_jp || '詳細なし'}\n`;
      report += `*   **推奨対策:** ${vuln.recommendation_jp || '情報なし'}\n\n`;
    }
  }

  console.log('Security report generation complete.');
  // console.log('Generated Report:\n', report); // For debugging
  return report;
}


// --- Main Execution Logic ---

async function run() {
  try {
    const token = core.getInput('github-token', { required: true });
    // severityLevel is no longer directly used for failure, but keep for potential future use?
    // const severityLevel = core.getInput('severity-level');

    const octokit = github.getOctokit(token);
    const context = github.context;

    if (context.eventName !== 'pull_request') {
      console.log(`Not a pull request event (${context.eventName}). Skipping scan.`);
      core.setOutput('status', 'skipped');
      return;
    }

    const pullRequest = context.payload.pull_request;
    if (!pullRequest) {
      core.setFailed('Pull request context not found.');
      return;
    }
    const issueNumber = pullRequest.number;
    const owner = context.repo.owner;
    const repo = context.repo.repo;

    console.log(`Starting security scan for PR #${issueNumber} in ${owner}/${repo}`);

    // 1. Get PR Diff
    const diff = await getDiffContent(octokit, owner, repo, issueNumber);
    if (!diff) return; // Error handled in getDiffContent

    // 2. Analyze Dependencies (using Perplexity)
    const dependencyAnalysis = await analyzeDependencies(diff);

    // 3. Analyze Vulnerabilities (using Perplexity, with dep context)
    const vulnerabilityResults = await analyzeVulnerabilities(diff, dependencyAnalysis.dependencies);

    // 4. Analyze Code Diffs for Updated Dependencies (using Gemini)
    const codeDiffAnalyses = {};
    if (dependencyAnalysis?.dependencies) {
      for (const dep of dependencyAnalysis.dependencies) {
        if (dep.change_type === 'updated') {
          const codeDiff = await getDependencyCodeDiff(dep.name, dep.version_change?.from, dep.version_change?.to);
          if (codeDiff) {
            codeDiffAnalyses[dep.name] = await analyzeCodeDiffWithGemini(codeDiff, dep.name, dep.version_change?.from, dep.version_change?.to);
          } else {
             codeDiffAnalyses[dep.name] = 'コード差分の取得失敗'; // Mark as failed if diff couldn't be obtained
          }
        }
      }
    }

    // 5. Generate Report
    const securityReport = generateSecurityReport(dependencyAnalysis, vulnerabilityResults, codeDiffAnalyses);

    // 6. Post Report as Comment
    await postComment(octokit, owner, repo, issueNumber, securityReport);

    // 7. Set Outputs and Warnings/Errors based on Overall Assessment
    const overallRecommendation = dependencyAnalysis.overall_assessment?.recommendation_jp || '判断不可';
    core.setOutput('overall_recommendation', overallRecommendation);
    core.setOutput('analysis_report', securityReport); // Output full report

    if (overallRecommendation === 'マージ前に対応必須') {
        core.error(`セキュリティレビューが必要です。総合評価: ${overallRecommendation}。理由: ${dependencyAnalysis.overall_assessment?.reasoning_jp || 'N/A'}`);
    } else if (overallRecommendation === '注意してマージ') {
        core.warning(`セキュリティ上の注意点があります。総合評価: ${overallRecommendation}。理由: ${dependencyAnalysis.overall_assessment?.reasoning_jp || 'N/A'}`);
    } else {
        core.notice(`スキャン完了。総合評価: ${overallRecommendation}。詳細はPRコメントを確認してください。`);
    }

  } catch (error) {
    core.setFailed(`アクション実行中に予期せぬエラーが発生しました: ${error.message}\n${error.stack}`);
    // Attempt to post a failure comment (best effort)
     try {
        const token = core.getInput('github-token');
        const octokit = github.getOctokit(token);
        const context = github.context;
        if (context.payload.pull_request) {
            await postComment(octokit, context.repo.owner, context.repo.repo, context.payload.pull_request.number,
             `セキュリティスキャン中にエラーが発生しました。\n\n\`\`\`\n${error.message}\n\`\`\`\n詳細はActionsのログを確認してください。`);
        }
     } catch (commentError) {
         console.error('失敗コメントの投稿中にさらにエラー:', commentError);
     }
  }
}

run();