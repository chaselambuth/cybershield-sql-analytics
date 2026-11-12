expression BundleRoot = "C:/Users/chase/Desktop/CyberShield Analytics/power_bi/data/bundle_38b300e881ec37bbe78d6b2e15502d714d37b286b57d2a9bcdb40485c8063193" meta [IsParameterQuery=true, Type="Text", IsParameterQueryRequired=true]
	annotation PBI_ResultType = Text

expression ExpectedPayloadId = "payload_3ff1a7f7b30ed35c16d5d6b3f34167e99a4a7006332139a068b4b403088f8b44"
	annotation PBI_ResultType = Text

expression BundleDocument =
		let
		    Raw = Json.Document(Binary.Buffer(File.Contents(BundleRoot & "/report_data.json"))),
		    Checked = if Raw[schema_version] = 1 and Raw[payload_id] = ExpectedPayloadId and Raw[validation][status] = "passed" then Raw
		        else error "Packed bundle identity, schema, or validation status differs. Regenerate for a new bundle."
		in Checked

expression LoadBundleTable =
		(name as text) as table =>
		let
		    Document = BundleDocument,
		    Spec = Record.Field(Document[schema], name),
		    Packed = Record.Field(Document[tables], name),
		    Names = List.Transform(Spec[columns], each _[name]),
		    Source = if Packed[columns] = Names then Table.FromRows(Packed[rows], Names) else error "Packed columns differ",
		    TypeMap = [text=type text, int64=Int64.Type, double=type number, boolean=type logical, datetime=type datetime],
		    Types = List.Transform(Spec[columns], each {_[name], Record.Field(TypeMap, _[type])}),
		    Typed = Table.Buffer(Table.TransformColumnTypes(Source, Types, "en-US")),
		    CountChecked = if Table.RowCount(Typed) = Spec[rows] then Typed else error "Packed row count differs",
		    Keys = if name = "Window" then {"window_key"} else if name = "SupportingFlows" then {"flow_id"}
		        else if name = "FactPrototypeDecision" then {"window_key", "detector_id"} else {},
		    Checked = if List.IsEmpty(Keys) or Table.RowCount(Table.Distinct(Table.SelectColumns(CountChecked, Keys))) = Spec[rows]
		        then CountChecked else error "Duplicate packed key"
		in Checked
