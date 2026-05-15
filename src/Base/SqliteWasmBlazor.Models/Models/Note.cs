using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SqliteWasmBlazor.Models.Models;

[Table("notes")]
public class Note
{
    [Key]
    [Column(TypeName = "BLOB")]
    public Guid Id { get; set; }

    [Required]
    [MaxLength(255)]
    public required string Title { get; set; }

    [Required]
    public required string Content { get; set; }

    [MaxLength(100)]
    public string? Tag { get; set; }

    [Column(TypeName = "BLOB")]
    public Guid? TodoId { get; set; }

    [Required]
    public DateTime CreatedAt { get; set; }

    public DateTime? ModifiedAt { get; set; }
}
