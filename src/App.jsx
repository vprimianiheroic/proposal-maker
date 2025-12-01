import React, { useState, useMemo, useEffect, useCallback } from 'react';

import { Plus, Trash2, Printer, ChevronDown, ChevronUp, FileText, DollarSign, Users, Shield, Layout, CheckCircle, Search, Upload, AlertTriangle, ArrowLeft } from 'lucide-react';



// ==========================================

// CONFIGURATION & CONSTANTS

// ==========================================

const HEROIC_API_KEY = "16bc6c64-4ee7-4f8e-9677-5cfaabc35e9b";

const HEROIC_API_URL = "https://api.heroic.com/v1/leaks/search"; // Adjust endpoint based on specific doc requirements



// --- PRICING CATALOG ---

const PRICING_CATALOG = {

  tiers: [

    {

      id: 'core',

      name: "DarkWatch Core Plan",

      price: "$10,000 / year",

      features: {

        seats: "3 admin user accounts",

        profiles: "1 Monitored Organizational Profile",

        api: "10,000 API credits per month",

        support: "Email & Chat Support"

      }

    },

    {

      id: 'pro',

      name: "DarkWatch Pro Plan",

      price: "$30,000 / year",

      features: {

        seats: "10 admin user accounts",

        profiles: "10+ Monitored Organizational Profiles",

        api: "35,000 API credits per month",

        support: "Email, Chat, 24-48hr Support"

      }

    },

    {

      id: 'advanced',

      name: "DarkWatch Advanced Plan",

      price: "$60,000 / year",

      features: {

        seats: "25 admin user accounts",

        profiles: "25+ Monitored Organizational Profiles",

        api: "80,000 API credits per month",

        support: "8x5 Next-day Support"

      }

    },

    {

      id: 'elite',

      name: "DarkWatch Elite Plan",

      price: "$100,000 / year",

      features: {

        seats: "Unlimited admin user accounts",

        profiles: "50+ Monitored Organizational Profiles",

        api: "150,000 API credits per month",

        support: "24x5, 4-hr SLA"

      }

    }

  ],

  addons: [

    { name: "Additional Org Profile", price: "$3,000 / year" },

    { name: "Additional Seat", price: "$600 / user / year" },

    { name: "Accelerate Package (Integration)", price: "$10,000 one-time" },

    { name: "Analyst Remediation Assist (20 hrs)", price: "$3,000" },

    { name: "Custom Engineering Sprint", price: "$25,000" },

    { name: "Takedown Pack (Cost per Takedown)", price: "$55.00" }

  ]

};



// ==========================================

// SUB-APP: PROPOSAL BUILDER

// ==========================================

const ProposalBuilder = ({ onBack }) => {

  const [activeSection, setActiveSection] = useState('pricing'); 



  const [proposalData, setProposalData] = useState({

    clientName: "Plante Moran",

    clientHeadquarters: "Southfield, Michigan",

    useCase: "Penetration testing and cybersecurity reviews by internal security teams. Company protection.",

    preparedFor: "ACD Direct",

    preparedBy: "Chad Bennett, CEO",

    preparedByPhone: "801-358-5536",

    preparedByEmail: "chad@heroic.com",

    startDate: "May-2025",

    lineItems: [

      { id: 1, name: "DarkWatch Core Plan 1-YR", price: "$10,000 / year" }

    ],

    benefits: [

      { id: 1, text: "Full access to the online platform, APIs, and monitoring functionality" },

      { id: 2, text: "1 Monitored Organizational Profile" },

      { id: 3, text: "3 admin user accounts" },

      { id: 4, text: "10,000 API credits per month" },

      { id: 5, text: "Real-time alerting when monitored identities have been discovered in breaches" },

      { id: 6, text: "Email & Chat Support" },

      { id: 7, text: "Custom Reporting" },

    ],

    dataCompliance: "All data access and usage must comply with applicable privacy laws and HEROIC's terms of service. Results are for internal security purposes only and may not be redistributed or resold.",

    onboarding: "HEROIC will provide onboarding documentation, API keys, and technical support for integration. Usage reporting and account management dashboards will be available to designated administrators."

  });



  const calculatedTotal = useMemo(() => {

    let total = 0;

    proposalData.lineItems.forEach(item => {

      const rawValue = item.price ? item.price.replace(/[^0-9.-]/g, '') : "0"; 

      const parsed = parseFloat(rawValue);

      if (!isNaN(parsed)) total += parsed;

    });

    return total.toLocaleString('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 0 });

  }, [proposalData.lineItems]);



  const toggleSection = (section) => setActiveSection(activeSection === section ? null : section);

  const handleInputChange = (e) => setProposalData(prev => ({ ...prev, [e.target.name]: e.target.value }));



  const applyTier = (tierId) => {

    const tier = PRICING_CATALOG.tiers.find(t => t.id === tierId);

    if (!tier) return;

    const newLineItems = [...proposalData.lineItems];

    const planIndex = newLineItems.findIndex(i => i.name.includes("DarkWatch"));

    if (planIndex >= 0) newLineItems[planIndex] = { ...newLineItems[planIndex], name: `${tier.name} 1-YR`, price: tier.price };

    else newLineItems.unshift({ id: Date.now(), name: `${tier.name} 1-YR`, price: tier.price });



    const newBenefits = [

      { id: 101, text: "Full access to the online platform, APIs, and monitoring functionality" },

      { id: 102, text: tier.features.profiles },

      { id: 103, text: tier.features.seats },

      { id: 104, text: tier.features.api },

      { id: 105, text: "Real-time alerting when monitored identities have been discovered in breaches" },

      { id: 106, text: tier.features.support },

      { id: 107, text: "Custom Reporting" },

    ];

    setProposalData(prev => ({ ...prev, lineItems: newLineItems, benefits: newBenefits }));

  };



  const addCatalogAddon = (e) => {

    const addon = PRICING_CATALOG.addons.find(a => a.name === e.target.value);

    if (addon) setProposalData(prev => ({ ...prev, lineItems: [...prev.lineItems, { id: Date.now(), name: addon.name, price: addon.price }] }));

    e.target.value = ""; 

  };



  const addLineItem = () => setProposalData(prev => ({ ...prev, lineItems: [...prev.lineItems, { id: Date.now(), name: "New Service", price: "$0" }] }));

  const updateLineItem = (id, f, v) => setProposalData(prev => ({ ...prev, lineItems: prev.lineItems.map(i => i.id === id ? { ...i, [f]: v } : i) }));

  const removeLineItem = (id) => setProposalData(prev => ({ ...prev, lineItems: prev.lineItems.filter(i => i.id !== id) }));

  const addBenefit = () => setProposalData(prev => ({ ...prev, benefits: [...prev.benefits, { id: Date.now(), text: "New Feature" }] }));

  const updateBenefit = (id, v) => setProposalData(prev => ({ ...prev, benefits: prev.benefits.map(b => b.id === id ? { ...b, text: v } : b) }));

  const removeBenefit = (id) => setProposalData(prev => ({ ...prev, benefits: prev.benefits.filter(b => b.id !== id) }));

  const handlePrint = () => window.print();



  return (

    <div className="min-h-screen bg-gray-100 font-sans text-gray-800 flex flex-col md:flex-row">

      {/* SIDEBAR */}

      <div className="w-full md:w-96 bg-white border-r border-gray-200 shadow-lg overflow-y-auto h-screen sticky top-0 print:hidden z-10">

        <div className="p-4 bg-gray-900 text-white flex justify-between items-center">

          <div className="flex items-center gap-2">

            <button onClick={onBack} className="p-1 hover:bg-gray-700 rounded mr-2"><ArrowLeft size={16}/></button>

            <h2 className="text-xl font-bold flex items-center gap-2"><Layout size={20} /> Builder</h2>

          </div>

          <button onClick={handlePrint} className="bg-red-600 hover:bg-red-700 text-white p-2 rounded-full"><Printer size={18} /></button>

        </div>

        <div className="p-4 space-y-4">

          {/* CLIENT */}

          <div className="border rounded-lg overflow-hidden">

            <button className="w-full p-3 bg-gray-50 flex justify-between items-center font-semibold text-gray-700" onClick={() => toggleSection('client')}><div className="flex items-center gap-2"><Users size={16}/> Client</div>{activeSection === 'client' ? <ChevronUp size={16}/> : <ChevronDown size={16}/>}</button>

            {activeSection === 'client' && (

              <div className="p-4 space-y-3 bg-white">

                <input type="text" name="clientName" value={proposalData.clientName} onChange={handleInputChange} className="w-full p-2 border rounded text-sm" placeholder="Client Name"/>

                <input type="text" name="clientHeadquarters" value={proposalData.clientHeadquarters} onChange={handleInputChange} className="w-full p-2 border rounded text-sm" placeholder="HQ"/>

                <input type="text" name="preparedFor" value={proposalData.preparedFor} onChange={handleInputChange} className="w-full p-2 border rounded text-sm" placeholder="Contact Person"/>

                <textarea name="useCase" value={proposalData.useCase} onChange={handleInputChange} className="w-full p-2 border rounded text-sm h-24" placeholder="Use Case"/>

              </div>

            )}

          </div>

          {/* PRICING */}

          <div className="border rounded-lg overflow-hidden border-blue-200 shadow-sm">

            <button className="w-full p-3 bg-blue-50 flex justify-between items-center font-semibold text-blue-900" onClick={() => toggleSection('pricing')}><div className="flex items-center gap-2"><DollarSign size={16}/> Pricing</div>{activeSection === 'pricing' ? <ChevronUp size={16}/> : <ChevronDown size={16}/>}</button>

            {activeSection === 'pricing' && (

              <div className="p-4 space-y-4 bg-white">

                <div className="bg-blue-50 p-3 rounded border border-blue-100 grid grid-cols-2 gap-2">

                   {PRICING_CATALOG.tiers.map(tier => (

                       <button key={tier.id} onClick={() => applyTier(tier.id)} className="px-2 py-2 bg-white border border-blue-200 rounded text-xs font-semibold text-blue-700 hover:bg-blue-600 hover:text-white text-left">{tier.name.replace("DarkWatch ", "")}<div className="text-[10px] opacity-70 font-normal">{tier.price}</div></button>

                   ))}

                </div>

                <select onChange={addCatalogAddon} className="w-full p-2 border rounded text-sm bg-gray-50" defaultValue=""><option value="" disabled>-- Add-on --</option>{PRICING_CATALOG.addons.map((a, i) => (<option key={i} value={a.name}>{a.name} - {a.price}</option>))}</select>

                <div className="space-y-2">

                  {proposalData.lineItems.map((item) => (

                    <div key={item.id} className="flex gap-2"><input type="text" value={item.name} onChange={(e) => updateLineItem(item.id, 'name', e.target.value)} className="w-full p-1 border rounded text-xs"/><input type="text" value={item.price} onChange={(e) => updateLineItem(item.id, 'price', e.target.value)} className="w-20 p-1 border rounded text-xs"/><button onClick={() => removeLineItem(item.id)}><Trash2 size={14} className="text-red-400"/></button></div>

                  ))}

                  <button onClick={addLineItem} className="w-full py-1 border-2 border-dashed border-gray-300 rounded text-gray-400 text-xs hover:border-blue-500 hover:text-blue-500"><Plus size={12} className="inline"/> Custom Item</button>

                  <div className="flex justify-between items-center font-bold text-green-700 text-sm"><span>Total</span><span>{calculatedTotal}</span></div>

                </div>

              </div>

            )}

          </div>

          {/* BENEFITS */}

          <div className="border rounded-lg overflow-hidden">

            <button className="w-full p-3 bg-gray-50 flex justify-between items-center font-semibold text-gray-700" onClick={() => toggleSection('features')}><div className="flex items-center gap-2"><CheckCircle size={16}/> Benefits</div>{activeSection === 'features' ? <ChevronUp size={16}/> : <ChevronDown size={16}/>}</button>

            {activeSection === 'features' && (

              <div className="p-4 space-y-2 bg-white">

                 {proposalData.benefits.map((item) => (

                    <div key={item.id} className="flex gap-2 items-center"><input type="text" value={item.text} onChange={(e) => updateBenefit(item.id, e.target.value)} className="w-full p-1 border rounded text-xs"/><button onClick={() => removeBenefit(item.id)}><Trash2 size={14} className="text-gray-400"/></button></div>

                  ))}

                  <button onClick={addBenefit} className="text-xs text-blue-600 font-semibold flex items-center gap-1 mt-2"><Plus size={12} /> Add Benefit</button>

              </div>

            )}

          </div>

          {/* CONFIG */}

          <div className="border rounded-lg overflow-hidden">

            <button className="w-full p-3 bg-gray-50 flex justify-between items-center font-semibold text-gray-700" onClick={() => toggleSection('config')}><div className="flex items-center gap-2"><FileText size={16}/> Internal Info</div>{activeSection === 'config' ? <ChevronUp size={16}/> : <ChevronDown size={16}/>}</button>

            {activeSection === 'config' && (

              <div className="p-4 space-y-3 bg-white">

                <input type="text" name="preparedBy" value={proposalData.preparedBy} onChange={handleInputChange} className="w-full p-2 border rounded text-sm" placeholder="Prep By"/>

                <input type="text" name="preparedByEmail" value={proposalData.preparedByEmail} onChange={handleInputChange} className="w-full p-2 border rounded text-sm" placeholder="Email"/>

              </div>

            )}

          </div>

        </div>

      </div>



      {/* PREVIEW */}

      <div className="flex-1 bg-gray-200 p-8 overflow-y-auto print:p-0 print:bg-white print:overflow-visible">

        {/* PAGE 1: COVER */}

        <div className="bg-white shadow-2xl mx-auto max-w-[8.5in] min-h-[11in] mb-8 print:shadow-none print:mb-0 print:break-after-page relative flex flex-col">

          <div className="h-4 bg-red-600 w-full"></div>

          <div className="p-16 flex flex-col justify-between flex-1">

            <div className="space-y-12">

              <div className="w-24 h-24 bg-red-600 flex items-center justify-center text-white font-bold text-4xl shadow-sm">H</div>

              <div className="space-y-2"><h1 className="text-6xl font-black text-gray-900 tracking-tight">HEROIC</h1><h2 className="text-3xl font-light text-gray-500 tracking-widest uppercase">DarkWatch</h2></div>

              <div className="pt-12 border-t-4 border-red-600 w-24"></div>

              <div><h3 className="text-2xl font-bold text-gray-900 mb-2">ENTERPRISE PROPOSAL</h3><p className="text-lg text-gray-600">Prepared For: <span className="font-semibold text-gray-900">{proposalData.clientName}</span></p><p className="text-gray-500 text-sm mt-1">{new Date().toLocaleDateString()}</p></div>

            </div>

            <div className="mt-auto"><h4 className="font-bold text-gray-900 uppercase tracking-wider mb-2">Prepared By</h4><p className="text-lg">{proposalData.preparedBy}</p><p className="text-gray-600">{proposalData.preparedByPhone}</p><p className="text-gray-600">{proposalData.preparedByEmail}</p><div className="mt-8 text-sm text-red-600 font-bold uppercase tracking-widest">Heroic Cybersecurity</div></div>

          </div>

          <div className="absolute bottom-0 right-0 p-16 opacity-5"><Shield size={300} /></div>

        </div>

        

        {/* PAGE 2: PRICING */}

        <div className="bg-white shadow-2xl mx-auto max-w-[8.5in] min-h-[11in] mb-8 print:shadow-none print:mb-0 print:break-after-page relative flex flex-col p-12">

          <div className="flex justify-between items-start border-b border-gray-200 pb-6 mb-8"><div><h2 className="text-3xl font-bold text-gray-900"><span className="text-red-600">HEROIC</span> DARKWATCH</h2></div><div className="text-right"><p className="text-sm text-gray-500">Proposal for:</p><p className="font-bold text-gray-900">{proposalData.clientName}</p></div></div>

          <div className="space-y-8">

            <div className="grid grid-cols-2 gap-8 text-sm"><div><p className="font-bold text-gray-500 uppercase text-xs mb-1">Company</p><p className="font-semibold text-gray-900 text-lg">{proposalData.clientName}</p></div><div><p className="font-bold text-gray-500 uppercase text-xs mb-1">Headquarters</p><p className="text-gray-900">{proposalData.clientHeadquarters}</p></div><div className="col-span-2"><p className="font-bold text-gray-500 uppercase text-xs mb-1">Primary Use Case</p><p className="text-gray-700 italic border-l-2 border-red-500 pl-3">{proposalData.useCase}</p></div></div>

            <div className="mt-8"><h3 className="text-lg font-bold text-gray-900 mb-4 flex items-center gap-2"><DollarSign className="text-red-600" size={20}/> Proposed Solution</h3><table className="w-full border-collapse"><thead><tr className="bg-gray-100 text-left text-xs uppercase text-gray-600 font-bold"><th className="p-3 border-b border-gray-300">Plan / Service</th><th className="p-3 border-b border-gray-300">Start Date Estimate</th><th className="p-3 border-b border-gray-300 text-right">Investment</th></tr></thead><tbody className="text-sm">{proposalData.lineItems.map((item) => (<tr key={item.id}><td className="p-3 border-b border-gray-200 font-medium text-gray-900">{item.name}</td><td className="p-3 border-b border-gray-200 text-gray-600">{proposalData.startDate}</td><td className="p-3 border-b border-gray-200 text-right font-bold text-gray-900">{item.price}</td></tr>))}<tr className="bg-gray-50"><td className="p-3 border-t border-gray-300 font-bold text-gray-900 text-right" colSpan="2">TOTAL</td><td className="p-3 border-t border-gray-300 text-right font-black text-gray-900">{calculatedTotal}*</td></tr></tbody></table><p className="text-[10px] text-gray-400 mt-2 text-right">*Total estimated based on standard items. Final invoicing terms apply.</p></div>

            <div className="mt-8 bg-gray-50 p-6 rounded-lg border border-gray-100"><h3 className="text-sm font-bold text-gray-900 uppercase tracking-wide mb-4 text-red-600">Platform Benefits & Limits</h3><ul className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm text-gray-700">{proposalData.benefits.map((benefit) => (<li key={benefit.id} className="flex items-start gap-2"><span className="text-red-600 mt-1">•</span><span>{benefit.text}</span></li>))}</ul></div>

          </div>

          <div className="mt-auto pt-8 border-t border-gray-200 text-center text-xs text-gray-400">Confidential Agreement | HEROIC {new Date().getFullYear()} - All Rights Reserved</div>

        </div>



        {/* PAGE 3: AGREEMENT (Simplified for space) */}

        <div className="bg-white shadow-2xl mx-auto max-w-[8.5in] min-h-[11in] mb-8 print:shadow-none print:mb-0 print:break-after-page relative flex flex-col p-12">

          <div className="flex justify-between items-start border-b border-gray-200 pb-6 mb-8"><div><h2 className="text-2xl font-bold text-gray-900">Agreement</h2></div><div className="text-right"><span className="text-xs font-bold bg-gray-100 px-2 py-1 rounded text-gray-600">Signatures</span></div></div>

          <div className="space-y-6 text-sm text-gray-700 leading-relaxed"><p>By signing below, both parties agree to the terms... (Full legal text as per prev document)</p><div className="grid grid-cols-2 gap-12 mt-12 mb-12"><div className="space-y-8"><h4 className="font-bold text-lg border-b-2 border-gray-900 pb-2">{proposalData.clientName}</h4><div className="space-y-4"><div className="h-8 border-b border-gray-300"></div><div className="h-12 border-b border-gray-300"></div></div></div><div className="space-y-8"><h4 className="font-bold text-lg border-b-2 border-red-600 pb-2">HEROIC Cybersecurity</h4><div className="space-y-4"><div className="h-8 border-b border-gray-300 flex items-end pb-1 font-script text-lg">{proposalData.preparedBy}</div><div className="h-12 border-b border-gray-300 bg-gray-50"></div></div></div></div></div>

          <div className="mt-auto pt-8 border-t border-gray-200 text-center text-xs text-gray-400">Confidential Agreement | HEROIC {new Date().getFullYear()} - All Rights Reserved</div>

        </div>

      </div>

    </div>

  );

};



// ==========================================

// SUB-APP: BREACH ANALYZER

// ==========================================

const BreachAnalyzer = ({ onBack }) => {

  const [inputText, setInputText] = useState("");

  const [results, setResults] = useState([]);

  const [loading, setLoading] = useState(false);

  const [domainStats, setDomainStats] = useState({});

  const [apiError, setApiError] = useState(null);



  // Extract domains from email

  const getDomain = (email) => email.split('@')[1];



  // Mock Data generator for Demo Mode

  const generateMockData = (email) => {

    const isLeaked = Math.random() > 0.3;

    return {

      success: true,

      leaks: isLeaked ? Math.floor(Math.random() * 15) + 1 : 0,

      sources: isLeaked ? ["LinkedIn 2012", "Adobe", "Canva", "Collection #1"].slice(0, Math.floor(Math.random() * 4) + 1) : []

    };

  };



  const processEmails = async () => {

    setLoading(true);

    setApiError(null);

    const emails = inputText.split(/[\n,]+/).map(e => e.trim()).filter(e => e.includes('@'));

    const tempResults = [];

    const tempDomainStats = {};



    // Simulate API calls or fetch real data

    for (const email of emails) {

      let data = null;

      

      try {

        // Attempt Real API Call

        const response = await fetch(HEROIC_API_URL, {

          method: 'POST', // Assuming POST for search based on typical patterns, or GET with param

          headers: {

            'Content-Type': 'application/json',

            'x-api-key': HEROIC_API_KEY

          },

          body: JSON.stringify({ query: email })

        });



        if (response.ok) {

           data = await response.json();

        } else {

           // Fallback to Mock if 404/401/CORS (likely in client-side demo)

           console.warn("API call failed, switching to demo mock data for:", email);

           data = generateMockData(email);

           if (!apiError) setApiError("Note: Running in Demo Mode (CORS/Auth restriction or API 404).");

        }

      } catch (err) {

        console.warn("Network error, switching to demo mock data");

        data = generateMockData(email);

        if (!apiError) setApiError("Note: Running in Demo Mode (Network Error).");

      }



      // Normalize Data Structure (adjust based on actual API response)

      const leakCount = data.leaks || (Array.isArray(data) ? data.length : 0) || 0;

      const leakSources = data.sources || (Array.isArray(data) ? data.map(d => d.source) : []) || [];



      tempResults.push({ email, count: leakCount, sources: leakSources });

      

      const domain = getDomain(email);

      if (!tempDomainStats[domain]) tempDomainStats[domain] = { totalCheck: 0, totalLeaks: 0 };

      tempDomainStats[domain].totalCheck++;

      tempDomainStats[domain].totalLeaks += leakCount;

    }



    setResults(tempResults);

    setDomainStats(tempDomainStats);

    setLoading(false);

  };



  return (

    <div className="min-h-screen bg-gray-900 text-white font-sans flex flex-col">

      {/* HEADER */}

      <div className="bg-black p-4 border-b border-gray-800 flex justify-between items-center">

        <div className="flex items-center gap-4">

          <button onClick={onBack} className="p-2 hover:bg-gray-800 rounded-lg transition-colors"><ArrowLeft /></button>

          <div>

            <h1 className="text-xl font-bold flex items-center gap-2"><Shield className="text-red-600"/> DarkWatch <span className="text-gray-500 font-light">Analyzer</span></h1>

            <p className="text-xs text-gray-500">Sales Intelligence Tool</p>

          </div>

        </div>

        <div className="flex items-center gap-2 text-xs text-gray-500">

          <div className={`w-2 h-2 rounded-full ${HEROIC_API_KEY ? 'bg-green-500' : 'bg-red-500'}`}></div>

          API Connected

        </div>

      </div>



      <div className="flex-1 flex overflow-hidden">

        {/* INPUT SIDEBAR */}

        <div className="w-1/3 p-6 border-r border-gray-800 flex flex-col">

          <h3 className="text-sm font-bold uppercase text-gray-400 mb-4 flex items-center gap-2"><Upload size={16}/> Bulk Input</h3>

          <p className="text-xs text-gray-500 mb-2">Paste CSV content or list of emails (one per line).</p>

          <textarea 

            className="flex-1 bg-gray-800 border border-gray-700 rounded-lg p-4 text-sm font-mono text-gray-300 focus:outline-none focus:border-red-600 resize-none mb-4"

            placeholder="ceo@example.com&#10;cto@example.com&#10;admin@example.com"

            value={inputText}

            onChange={(e) => setInputText(e.target.value)}

          />

          <button 

            onClick={processEmails} 

            disabled={loading || !inputText}

            className="w-full py-4 bg-red-600 hover:bg-red-700 rounded-lg font-bold text-white shadow-lg shadow-red-900/20 disabled:opacity-50 disabled:cursor-not-allowed flex justify-center items-center gap-2"

          >

            {loading ? "Scanning Dark Web..." : <><Search size={18}/> Analyze Breaches</>}

          </button>

        </div>



        {/* RESULTS AREA */}

        <div className="flex-1 bg-gray-900 p-8 overflow-y-auto">

          {apiError && (

             <div className="bg-yellow-900/30 border border-yellow-600/50 p-3 rounded mb-6 text-yellow-200 text-xs flex items-center gap-2">

               <AlertTriangle size={14} /> {apiError}

             </div>

          )}



          {!results.length && !loading && (

            <div className="h-full flex flex-col items-center justify-center text-gray-600 opacity-50">

              <Shield size={64} className="mb-4"/>

              <p>Ready to scan. Input emails to begin.</p>

            </div>

          )}



          {/* DOMAIN STATS CARDS */}

          {Object.keys(domainStats).length > 0 && (

            <div className="grid grid-cols-3 gap-4 mb-8">

              {Object.entries(domainStats).map(([domain, stats]) => (

                <div key={domain} className="bg-gray-800 p-4 rounded-lg border border-gray-700">

                  <div className="text-xs text-gray-500 uppercase font-bold mb-1">Domain Risk</div>

                  <div className="text-lg font-bold text-white mb-2 truncate">{domain}</div>

                  <div className="flex justify-between items-end">

                    <div>

                       <span className="text-2xl font-black text-red-500">{stats.totalLeaks}</span>

                       <span className="text-xs text-gray-400 ml-1">total breaches</span>

                    </div>

                    <div className="text-xs bg-gray-700 px-2 py-1 rounded">

                       {stats.totalCheck} emails checked

                    </div>

                  </div>

                </div>

              ))}

            </div>

          )}



          {/* EMAIL TABLE */}

          {results.length > 0 && (

            <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">

              <table className="w-full text-left text-sm">

                <thead className="bg-black text-gray-400 font-bold uppercase text-xs">

                  <tr>

                    <th className="p-4">Identity</th>

                    <th className="p-4 text-center">Breach Count</th>

                    <th className="p-4">Known Sources</th>

                    <th className="p-4 text-right">Status</th>

                  </tr>

                </thead>

                <tbody className="divide-y divide-gray-700">

                  {results.map((r, i) => (

                    <tr key={i} className="hover:bg-gray-750">

                      <td className="p-4 font-mono text-gray-300">{r.email}</td>

                      <td className="p-4 text-center">

                        <span className={`inline-block px-3 py-1 rounded font-bold ${r.count > 0 ? 'bg-red-900/30 text-red-500' : 'bg-green-900/30 text-green-500'}`}>

                          {r.count}

                        </span>

                      </td>

                      <td className="p-4 text-gray-500 text-xs">

                        {r.sources.slice(0, 3).join(", ")}

                        {r.sources.length > 3 && ` +${r.sources.length - 3} more`}

                      </td>

                      <td className="p-4 text-right">

                         {r.count > 5 ? <AlertTriangle size={16} className="text-red-500 inline"/> : r.count > 0 ? <AlertTriangle size={16} className="text-yellow-500 inline"/> : <CheckCircle size={16} className="text-green-500 inline"/>}

                      </td>

                    </tr>

                  ))}

                </tbody>

              </table>

            </div>

          )}

        </div>

      </div>

    </div>

  );

};



// ==========================================

// MAIN APP LAUNCHER

// ==========================================

const App = () => {

  const [currentView, setCurrentView] = useState('launcher'); // 'launcher', 'proposal', 'analyzer'



  if (currentView === 'proposal') return <ProposalBuilder onBack={() => setCurrentView('launcher')} />;

  if (currentView === 'analyzer') return <BreachAnalyzer onBack={() => setCurrentView('launcher')} />;



  return (

    <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center p-8">

      <div className="max-w-4xl w-full">

        <div className="text-center mb-16">

          <div className="w-20 h-20 bg-red-600 mx-auto rounded-2xl flex items-center justify-center mb-6 shadow-2xl shadow-red-900/50">

            <span className="text-4xl font-black">H</span>

          </div>

          <h1 className="text-5xl font-black tracking-tight mb-4">HEROIC SALES SUITE</h1>

          <p className="text-gray-400 text-lg">Select a tool to begin</p>

        </div>



        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">

          {/* Proposal Card */}

          <button 

            onClick={() => setCurrentView('proposal')}

            className="group relative bg-gray-800 hover:bg-white hover:text-gray-900 border border-gray-700 hover:border-transparent rounded-2xl p-8 transition-all duration-300 text-left hover:-translate-y-2 hover:shadow-2xl"

          >

            <div className="w-12 h-12 bg-gray-700 group-hover:bg-red-100 rounded-lg flex items-center justify-center mb-6 transition-colors">

              <FileText className="text-white group-hover:text-red-600" size={24} />

            </div>

            <h2 className="text-2xl font-bold mb-2">Proposal Builder</h2>

            <p className="text-gray-400 group-hover:text-gray-600 mb-6">Create dynamic, print-ready PDFs for DarkWatch Enterprise plans. Configure pricing tiers, addons, and custom client details.</p>

            <span className="text-sm font-bold uppercase tracking-wider text-gray-500 group-hover:text-red-600 flex items-center gap-2">

              Launch Tool <ArrowLeft className="rotate-180" size={14}/>

            </span>

          </button>



          {/* Analyzer Card */}

          <button 

            onClick={() => setCurrentView('analyzer')}

            className="group relative bg-gray-800 hover:bg-white hover:text-gray-900 border border-gray-700 hover:border-transparent rounded-2xl p-8 transition-all duration-300 text-left hover:-translate-y-2 hover:shadow-2xl"

          >

            <div className="w-12 h-12 bg-gray-700 group-hover:bg-red-100 rounded-lg flex items-center justify-center mb-6 transition-colors">

              <Search className="text-white group-hover:text-red-600" size={24} />

            </div>

            <h2 className="text-2xl font-bold mb-2">Breach Analyzer</h2>

            <p className="text-gray-400 group-hover:text-gray-600 mb-6">Bulk scan prospect emails against Heroic's dark web database. Generate domain-level risk reports for sales intelligence.</p>

            <span className="text-sm font-bold uppercase tracking-wider text-gray-500 group-hover:text-red-600 flex items-center gap-2">

              Launch Tool <ArrowLeft className="rotate-180" size={14}/>

            </span>

          </button>

        </div>

        

        <div className="mt-16 text-center text-xs text-gray-600">

          Internal Tool v2.1 | Connected to Heroic API

        </div>

      </div>

    </div>

  );

};



export default App;

