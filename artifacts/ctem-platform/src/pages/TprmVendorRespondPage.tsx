import { useEffect, useState } from "react";
import { useParams } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, Loader2, Paperclip, Shield, Star } from "lucide-react";
import { apiFetch } from "@/lib/apiFetch";

interface QuestionDef {
  id: string;
  text: string;
  type: "boolean" | "text" | "rating" | "select" | "file";
  category: string;
  required: boolean;
  options?: string[];
}

interface QuestionnaireInfo {
  id: number;
  status: string;
  dueDate: string | null;
  vendorName: string;
  templateName: string;
  questions: QuestionDef[];
  alreadyCompleted: boolean;
}

export default function TprmVendorRespondPage() {
  const { token } = useParams<{ token: string }>();
  const [info, setInfo]       = useState<QuestionnaireInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);
  const [answers, setAnswers] = useState<Record<string, any>>({});
  const [respondedBy, setRespondedBy] = useState("");
  const [submitting, setSubmitting]   = useState(false);
  const [submitted, setSubmitted]     = useState(false);
  const [result, setResult]   = useState<{ score: number; riskLevel: string; message: string } | null>(null);

  useEffect(() => {
    fetch(`/api/tprm/respond/${token}`)
      .then(r => r.json())
      .then(d => {
        if (d.error) { setError(d.error); }
        else { setInfo(d); if (d.alreadyCompleted) setSubmitted(true); }
      })
      .catch(() => setError("Failed to load questionnaire"))
      .finally(() => setLoading(false));
  }, [token]);

  const setAnswer = (id: string, value: any) => setAnswers(a => ({ ...a, [id]: value }));

  const submit = async () => {
    if (!info) return;
    const responses = info.questions.map(q => ({ questionId: q.id, answer: answers[q.id] ?? null }));
    setSubmitting(true);
    try {
      const r = await fetch(`/api/tprm/respond/${token}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ responses, respondedBy }),
      }).then(r => r.json());
      if (r.error) throw new Error(r.error);
      setResult(r);
      setSubmitted(true);
    } catch (err: any) {
      setError(err.message ?? "Submission failed");
    }
    setSubmitting(false);
  };

  if (loading) return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <Skeleton className="w-full max-w-xl h-64" />
    </div>
  );

  if (error) return (
    <div className="min-h-screen bg-background flex items-center justify-center p-6">
      <Card className="max-w-md w-full">
        <CardContent className="py-12 text-center">
          <Shield className="w-12 h-12 text-red-400 mx-auto mb-4" />
          <p className="text-lg font-semibold">Unable to Load Questionnaire</p>
          <p className="text-sm text-muted-foreground mt-2">{error}</p>
        </CardContent>
      </Card>
    </div>
  );

  if (submitted) return (
    <div className="min-h-screen bg-background flex items-center justify-center p-6">
      <Card className="max-w-md w-full">
        <CardContent className="py-12 text-center">
          <CheckCircle2 className="w-12 h-12 text-green-400 mx-auto mb-4" />
          <p className="text-lg font-semibold">Response Submitted</p>
          <p className="text-sm text-muted-foreground mt-2">
            {result?.message ?? "Thank you — your security questionnaire has been recorded."}
          </p>
          {result && (
            <div className="mt-4 flex items-center justify-center gap-3">
              <div className="text-center">
                <p className="text-3xl font-bold">{result.score}</p>
                <p className="text-xs text-muted-foreground">Score</p>
              </div>
              <Badge variant="outline" className="capitalize">{result.riskLevel} risk</Badge>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );

  if (!info) return null;

  const categories = [...new Set(info.questions.map(q => q.category))];

  return (
    <div className="min-h-screen bg-background py-10 px-4">
      <div className="max-w-2xl mx-auto space-y-6">
        {/* Header */}
        <div className="text-center space-y-2">
          <div className="flex items-center justify-center gap-2">
            <Shield className="w-8 h-8 text-primary" />
            <h1 className="text-2xl font-bold">Security Questionnaire</h1>
          </div>
          <p className="text-muted-foreground">For: <span className="font-medium text-foreground">{info.vendorName}</span></p>
          <p className="text-sm text-muted-foreground">{info.templateName}</p>
          {info.dueDate && <p className="text-xs text-muted-foreground">Due: {new Date(info.dueDate).toLocaleDateString()}</p>}
        </div>

        {/* Respondent */}
        <Card>
          <CardContent className="pt-4 pb-3">
            <Label className="text-xs">Your Name / Email</Label>
            <Input className="mt-1" placeholder="e.g. John Smith, security@company.com" value={respondedBy} onChange={e => setRespondedBy(e.target.value)} />
          </CardContent>
        </Card>

        {/* Questions by category */}
        {categories.map(cat => {
          const qs = info.questions.filter(q => q.category === cat);
          return (
            <Card key={cat}>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm capitalize">{cat.replace(/_/g, " ")}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {qs.map((q, i) => (
                  <div key={q.id} className="space-y-1.5">
                    <Label className="text-sm font-normal">
                      {i + 1}. {q.text}
                      {q.required && <span className="text-red-400 ml-1">*</span>}
                    </Label>
                    {q.type === "boolean" && (
                      <div className="flex gap-2">
                        {["Yes", "No"].map(opt => (
                          <button key={opt} onClick={() => setAnswer(q.id, opt === "Yes")}
                            className={`flex-1 py-2 rounded border text-sm font-medium transition-colors ${
                              (answers[q.id] === true && opt === "Yes") || (answers[q.id] === false && opt === "No")
                                ? "bg-primary text-primary-foreground border-primary"
                                : "border-border hover:bg-accent"
                            }`}>
                            {opt}
                          </button>
                        ))}
                      </div>
                    )}
                    {q.type === "rating" && (
                      <div className="flex gap-1">
                        {[1, 2, 3, 4, 5].map(n => (
                          <button key={n} onClick={() => setAnswer(q.id, n)}
                            className={`w-10 h-10 rounded border text-sm font-medium transition-colors flex items-center justify-center ${
                              answers[q.id] === n ? "bg-primary text-primary-foreground border-primary" : "border-border hover:bg-accent"
                            }`}>
                            {n}
                          </button>
                        ))}
                      </div>
                    )}
                    {q.type === "text" && (
                      <Textarea rows={2} className="text-sm" value={answers[q.id] ?? ""} onChange={e => setAnswer(q.id, e.target.value)} placeholder="Your answer…" />
                    )}
                    {q.type === "select" && q.options && (
                      <div className="flex flex-wrap gap-2">
                        {q.options.map(opt => (
                          <button key={opt} onClick={() => setAnswer(q.id, opt)}
                            className={`px-3 py-1.5 rounded border text-sm transition-colors ${
                              answers[q.id] === opt ? "bg-primary text-primary-foreground border-primary" : "border-border hover:bg-accent"
                            }`}>
                            {opt}
                          </button>
                        ))}
                      </div>
                    )}
                    {q.type === "file" && (
                      <div className="space-y-2">
                        <div className="flex items-center gap-2">
                          <label className="flex items-center gap-2 cursor-pointer px-3 py-2 rounded border border-dashed border-border hover:bg-accent text-sm text-muted-foreground transition-colors">
                            <Paperclip className="w-4 h-4" />
                            {answers[q.id]?.name ?? "Choose file to upload…"}
                            <input type="file" className="hidden" onChange={async e => {
                              const file = e.target.files?.[0];
                              if (!file) return;
                              const fd = new FormData();
                              fd.append("file", file);
                              try {
                                const r = await fetch(`/api/tprm/questionnaire-respond-file/${token}/${q.id}`, { method: "POST", body: fd });
                                const data = await r.json();
                                if (data.ok) setAnswer(q.id, { name: file.name, ref: data.fileName });
                              } catch { /* ignore */ }
                            }} />
                          </label>
                          {answers[q.id]?.name && (
                            <span className="text-xs text-green-400 flex items-center gap-1">
                              <CheckCircle2 className="w-3.5 h-3.5" />{answers[q.id].name} uploaded
                            </span>
                          )}
                        </div>
                        <p className="text-[10px] text-muted-foreground">Accepted: PDF, DOCX, images, spreadsheets. Max 10 MB.</p>
                      </div>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          );
        })}

        <Button className="w-full" size="lg" onClick={submit} disabled={submitting}>
          {submitting ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Submitting…</> : "Submit Questionnaire"}
        </Button>
        <p className="text-xs text-center text-muted-foreground">Your responses are securely transmitted and stored by Sentinelware.</p>
      </div>
    </div>
  );
}
