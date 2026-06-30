import { useEffect } from "react";
import { useLocation } from "wouter";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";

interface RequireAiMapperProps {
  children: React.ReactNode;
}

export function RequireAiMapper({ children }: RequireAiMapperProps) {
  const { aiMapperEnabled, isAuthenticated } = useAuth();
  const [, navigate] = useLocation();
  const { toast } = useToast();

  useEffect(() => {
    if (isAuthenticated && aiMapperEnabled === false) {
      toast({
        title: "AI Mapper not enabled",
        description: "AI Mapper module is not enabled for your organization.",
        variant: "destructive",
      });
      navigate("/dashboard");
    }
  }, [aiMapperEnabled, isAuthenticated, navigate, toast]);

  if (!isAuthenticated || aiMapperEnabled === false) return null;

  return <>{children}</>;
}
