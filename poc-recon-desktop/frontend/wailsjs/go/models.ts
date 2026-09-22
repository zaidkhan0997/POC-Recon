export namespace bulk {
	
	export class EnrichedLeadExport {
	    full_name: string;
	    first_name: string;
	    last_name: string;
	    domain: string;
	    email: string;
	    confidence: number;
	    status: string;
	    pattern: string;
	    mail_provider: string;
	    verified_at: string;
	    alternatives?: string[];
	    alternative_emails?: string;
	
	    static createFrom(source: any = {}) {
	        return new EnrichedLeadExport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.full_name = source["full_name"];
	        this.first_name = source["first_name"];
	        this.last_name = source["last_name"];
	        this.domain = source["domain"];
	        this.email = source["email"];
	        this.confidence = source["confidence"];
	        this.status = source["status"];
	        this.pattern = source["pattern"];
	        this.mail_provider = source["mail_provider"];
	        this.verified_at = source["verified_at"];
	        this.alternatives = source["alternatives"];
	        this.alternative_emails = source["alternative_emails"];
	    }
	}
	export class LeadTarget {
	    domain: string;
	    full_name: string;
	    first_name?: string;
	    last_name?: string;
	    person_linkedin?: string;
	    company_linkedin?: string;
	
	    static createFrom(source: any = {}) {
	        return new LeadTarget(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.domain = source["domain"];
	        this.full_name = source["full_name"];
	        this.first_name = source["first_name"];
	        this.last_name = source["last_name"];
	        this.person_linkedin = source["person_linkedin"];
	        this.company_linkedin = source["company_linkedin"];
	    }
	}

}

export namespace cache {
	
	export class SavedLead {
	    id: string;
	    full_name: string;
	    first_name: string;
	    last_name: string;
	    domain: string;
	    email: string;
	    pattern_name: string;
	    confidence: number;
	    status: string;
	    provider: string;
	    // Go type: time
	    verified_at: any;
	
	    static createFrom(source: any = {}) {
	        return new SavedLead(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.full_name = source["full_name"];
	        this.first_name = source["first_name"];
	        this.last_name = source["last_name"];
	        this.domain = source["domain"];
	        this.email = source["email"];
	        this.pattern_name = source["pattern_name"];
	        this.confidence = source["confidence"];
	        this.status = source["status"];
	        this.provider = source["provider"];
	        this.verified_at = this.convertValues(source["verified_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace main {
	
	export class ReconRequest {
	    website: string;
	    name: string;
	    person_linkedin: string;
	    company_linkedin: string;
	    pattern: string;
	    proxy_url: string;
	    no_verify: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ReconRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.website = source["website"];
	        this.name = source["name"];
	        this.person_linkedin = source["person_linkedin"];
	        this.company_linkedin = source["company_linkedin"];
	        this.pattern = source["pattern"];
	        this.proxy_url = source["proxy_url"];
	        this.no_verify = source["no_verify"];
	    }
	}

}

export namespace models {
	
	export class CandidateResult {
	    email: string;
	    pattern_name: string;
	    status: string;
	    confidence: number;
	    smtp_code?: number;
	    smtp_message?: string;
	
	    static createFrom(source: any = {}) {
	        return new CandidateResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.email = source["email"];
	        this.pattern_name = source["pattern_name"];
	        this.status = source["status"];
	        this.confidence = source["confidence"];
	        this.smtp_code = source["smtp_code"];
	        this.smtp_message = source["smtp_message"];
	    }
	}
	export class MXRecord {
	    host: string;
	    priority: number;
	
	    static createFrom(source: any = {}) {
	        return new MXRecord(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.priority = source["priority"];
	    }
	}
	export class NameParts {
	    first_name: string;
	    middle_name?: string;
	    last_name?: string;
	    raw_name: string;
	    full_name: string;
	
	    static createFrom(source: any = {}) {
	        return new NameParts(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.first_name = source["first_name"];
	        this.middle_name = source["middle_name"];
	        this.last_name = source["last_name"];
	        this.raw_name = source["raw_name"];
	        this.full_name = source["full_name"];
	    }
	}
	export class ProviderInfo {
	    name: string;
	    spf_record?: string;
	    details?: string;
	
	    static createFrom(source: any = {}) {
	        return new ProviderInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.spf_record = source["spf_record"];
	        this.details = source["details"];
	    }
	}
	export class ReconResult {
	    target_domain: string;
	    person: NameParts;
	    mx_records: MXRecord[];
	    provider?: ProviderInfo;
	    port_25_open: boolean;
	    is_catch_all: boolean;
	    detected_pattern?: string;
	    detected_pattern_source?: string;
	    discovered_domain_emails?: string[];
	    verification_method: string;
	    candidates: CandidateResult[];
	    best_candidate?: CandidateResult;
	    // Go type: time
	    timestamp: any;
	
	    static createFrom(source: any = {}) {
	        return new ReconResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target_domain = source["target_domain"];
	        this.person = this.convertValues(source["person"], NameParts);
	        this.mx_records = this.convertValues(source["mx_records"], MXRecord);
	        this.provider = this.convertValues(source["provider"], ProviderInfo);
	        this.port_25_open = source["port_25_open"];
	        this.is_catch_all = source["is_catch_all"];
	        this.detected_pattern = source["detected_pattern"];
	        this.detected_pattern_source = source["detected_pattern_source"];
	        this.discovered_domain_emails = source["discovered_domain_emails"];
	        this.verification_method = source["verification_method"];
	        this.candidates = this.convertValues(source["candidates"], CandidateResult);
	        this.best_candidate = this.convertValues(source["best_candidate"], CandidateResult);
	        this.timestamp = this.convertValues(source["timestamp"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

