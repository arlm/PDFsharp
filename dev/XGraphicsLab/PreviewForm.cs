using System;
using System.Diagnostics;
using System.Drawing;
using System.Collections;
using System.ComponentModel;
using System.Windows.Forms;
using PdfSharp;
using PdfSharp.Pdf;
using PdfSharp.Drawing;
using PdfSharp.Forms;

namespace XDrawing.TestLab
{
  /// <summary>
  /// Preview form.
  /// </summary>
  public class PreviewForm : System.Windows.Forms.Form
  {
    private System.ComponentModel.IContainer components;

    public PreviewForm()
    {
      InitializeComponent();

      UITools.MakeDialogSizable(this);
      this.Refresh();

      this.pagePreview.Size = PageSizeConverter.ToSize(PageSize.A3).ToSizeF().ToSize();

      UpdateStatusBar();
      Screen screen = Screen.FromControl(this);
      Rectangle rect = screen.Bounds;
      this.Bounds = new Rectangle(rect.Width / 2 - 2, 2, rect.Width / 2, rect.Height / 2);
      //this.FormBorderStyle = FormBorderStyle.Sizable;
    }
    private System.Windows.Forms.StatusBar statusBar;
    private System.Windows.Forms.ToolBarButton tbbFirstPage;
    private System.Windows.Forms.ToolBarButton tbbSeparator1;
    private System.Windows.Forms.ImageList ilToolbar;
    private System.Windows.Forms.ToolBarButton tbbPrevPage;
    private System.Windows.Forms.ToolBarButton tbbNextPage;
    private System.Windows.Forms.ToolBarButton tbbLastPage;
    private System.Windows.Forms.ToolBarButton tbbSeparator2;
    private System.Windows.Forms.ToolBarButton tbbOriginalSize;
    private System.Windows.Forms.ToolBarButton tbbFullPage;
    private System.Windows.Forms.ToolBarButton tbbBestFit;
    private System.Windows.Forms.ToolBarButton tbbSmaller;
    private System.Windows.Forms.ToolBarButton tbbLarger;
    private System.Windows.Forms.ToolBarButton tbbSeparator3;
    private System.Windows.Forms.ToolBarButton tbbMakePdf;
    private System.Windows.Forms.ToolBar toolBar;
    private System.Windows.Forms.MenuItem menuItem10;
    private System.Windows.Forms.MenuItem miPercent800;
    private System.Windows.Forms.MenuItem miPercent600;
    private System.Windows.Forms.MenuItem miPercent400;
    private System.Windows.Forms.MenuItem miPercent200;
    private System.Windows.Forms.MenuItem miPercent150;
    private System.Windows.Forms.MenuItem miPercent75;
    private System.Windows.Forms.MenuItem miPercent50;
    private System.Windows.Forms.MenuItem miPercent25;
    private System.Windows.Forms.MenuItem miPercent10;
    private System.Windows.Forms.MenuItem miBestFit;
    private System.Windows.Forms.MenuItem miFullPage;
    private System.Windows.Forms.ContextMenu menuZoom;
    private System.Windows.Forms.MenuItem miPercent100;
    private MenuItem miOriginalSize;
    private PdfSharp.Forms.PagePreview pagePreview;

    public void SetRenderEvent(PagePreview.RenderEvent renderEvent)
    {
      this.pagePreview.SetRenderEvent(renderEvent);
      this.renderEvent = renderEvent;
      UpdateStatusBar();
    }
    PagePreview.RenderEvent renderEvent;

    public void UpdateDrawing()
    {
      this.pagePreview.Invalidate();
      UpdateStatusBar();
    }

    /// <summary>
    /// Clean up any resources being used.
    /// </summary>
    protected override void Dispose(bool disposing)
    {
      if (disposing)
      {
        if (components != null)
          components.Dispose();
      }
      base.Dispose(disposing);
    }

    void MakePdf()
    {
      // Let's torture the garbage collector...
      const int fileCount = 1;
      const int pageCount = 1;

      string lastFilename = "";
      for (int fileIdx = 0; fileIdx < fileCount; fileIdx++)
      {
        string filename = Guid.NewGuid().ToString().ToUpper() + ".pdf";
        //PdfSharp.Drawing.XGraphic gfx = new PdfSharp.Drawing.XGraphic();
        PdfDocument document = new PdfDocument(filename);
        document.Options.ColorMode = XGraphicsLab.properties.General.ColorMode;
#if true_
      DateTime now = DateTime.Now;
      for (int i = 0; i < 10000000; i++)
        document.Info.Title = "Hallö €-δ-α-β-☺♥♦♠♣x";
      TimeSpan span = DateTime.Now - now;
      Debug.WriteLine("span = " + span.TotalSeconds.ToString());
#endif
        for (int pageIdx = 0; pageIdx < pageCount; pageIdx++)
        {
          PdfPage page = document.AddPage();
          page.Size = PageSize.A4;
          XGraphics gfx = XGraphics.FromPdfPage(page, XGraphicsLab.properties.General.PageDirection);
          if (this.renderEvent != null)
            this.renderEvent(gfx);
        }
        //document.WriteToFile(filename);
#if true_
        // Check protection
        document.SecuritySettings.UserPassword = "x";
        document.SecuritySettings.OwnerPassword = "y";
        //document.SecuritySettings.PermitModifyDocument = false;
        //document.SecuritySettings.PermitPrint = true;
#endif
        document.Close();
        lastFilename = filename;
      }
      UpdateStatusBar();
      Process.Start(lastFilename);
    }

    int GetNewZoom(int currentZoom, bool larger)
    {
      int[] values = new int[]
      {
        10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 120, 140, 160, 180, 200, 
        250, 300, 350, 400, 450, 500, 600, 700, 800
      };

      if (currentZoom <= (int)Zoom.Mininum && !larger)
        return (int)Zoom.Mininum;
      else if (currentZoom >= (int)Zoom.Maximum && larger)
        return (int)Zoom.Maximum;

      if (larger)
      {
        for (int i = 0; i < values.Length; i++)
        {
          if (currentZoom < values[i])
            return values[i];
        }
      }
      else
      {
        for (int i = values.Length - 1; i >= 0; i--)
        {
          if (currentZoom > values[i])
            return values[i];
        }
      }
      return (int)Zoom.Percent100;
    }

    void UpdateStatusBar()
    {
      string status = String.Format("PageSize: {0}pt x {1}pt, Zoom: {2}%, TotalMemory: {3}",
        this.pagePreview.PageSize.Width, this.pagePreview.PageSize.Height,
        this.pagePreview.ZoomPercent, GC.GetTotalMemory(true));
      this.statusBar.Text = status;
    }


    #region Windows Form Designer generated code
    /// <summary>
    /// Required method for Designer support - do not modify
    /// the contents of this method with the code editor.
    /// </summary>
    private void InitializeComponent()
    {
      this.components = new System.ComponentModel.Container();
      System.Resources.ResourceManager resources = new System.Resources.ResourceManager(typeof(PreviewForm));
      this.toolBar = new System.Windows.Forms.ToolBar();
      this.tbbSeparator1 = new System.Windows.Forms.ToolBarButton();
      this.tbbFirstPage = new System.Windows.Forms.ToolBarButton();
      this.tbbPrevPage = new System.Windows.Forms.ToolBarButton();
      this.tbbNextPage = new System.Windows.Forms.ToolBarButton();
      this.tbbLastPage = new System.Windows.Forms.ToolBarButton();
      this.tbbSeparator2 = new System.Windows.Forms.ToolBarButton();
      this.tbbOriginalSize = new System.Windows.Forms.ToolBarButton();
      this.menuZoom = new System.Windows.Forms.ContextMenu();
      this.miPercent800 = new System.Windows.Forms.MenuItem();
      this.miPercent600 = new System.Windows.Forms.MenuItem();
      this.miPercent400 = new System.Windows.Forms.MenuItem();
      this.miPercent200 = new System.Windows.Forms.MenuItem();
      this.miPercent150 = new System.Windows.Forms.MenuItem();
      this.miPercent100 = new System.Windows.Forms.MenuItem();
      this.miPercent75 = new System.Windows.Forms.MenuItem();
      this.miPercent50 = new System.Windows.Forms.MenuItem();
      this.miPercent25 = new System.Windows.Forms.MenuItem();
      this.miPercent10 = new System.Windows.Forms.MenuItem();
      this.menuItem10 = new System.Windows.Forms.MenuItem();
      this.miOriginalSize = new System.Windows.Forms.MenuItem();
      this.miBestFit = new System.Windows.Forms.MenuItem();
      this.miFullPage = new System.Windows.Forms.MenuItem();
      this.tbbFullPage = new System.Windows.Forms.ToolBarButton();
      this.tbbBestFit = new System.Windows.Forms.ToolBarButton();
      this.tbbSmaller = new System.Windows.Forms.ToolBarButton();
      this.tbbLarger = new System.Windows.Forms.ToolBarButton();
      this.tbbSeparator3 = new System.Windows.Forms.ToolBarButton();
      this.tbbMakePdf = new System.Windows.Forms.ToolBarButton();
      this.ilToolbar = new System.Windows.Forms.ImageList(this.components);
      this.statusBar = new System.Windows.Forms.StatusBar();
      this.pagePreview = new PdfSharp.Forms.PagePreview();
      this.SuspendLayout();
      // 
      // toolBar
      // 
      this.toolBar.Appearance = System.Windows.Forms.ToolBarAppearance.Flat;
      this.toolBar.Buttons.AddRange(new System.Windows.Forms.ToolBarButton[] {
                                                                               this.tbbSeparator1,
                                                                               this.tbbFirstPage,
                                                                               this.tbbPrevPage,
                                                                               this.tbbNextPage,
                                                                               this.tbbLastPage,
                                                                               this.tbbSeparator2,
                                                                               this.tbbOriginalSize,
                                                                               this.tbbFullPage,
                                                                               this.tbbBestFit,
                                                                               this.tbbSmaller,
                                                                               this.tbbLarger,
                                                                               this.tbbSeparator3,
                                                                               this.tbbMakePdf});
      this.toolBar.DropDownArrows = true;
      this.toolBar.ImageList = this.ilToolbar;
      this.toolBar.Location = new System.Drawing.Point(0, 0);
      this.toolBar.Name = "toolBar";
      this.toolBar.ShowToolTips = true;
      this.toolBar.Size = new System.Drawing.Size(638, 42);
      this.toolBar.TabIndex = 1;
      this.toolBar.ButtonClick += new System.Windows.Forms.ToolBarButtonClickEventHandler(this.toolBar_ButtonClick);
      // 
      // tbbSeparator1
      // 
      this.tbbSeparator1.Style = System.Windows.Forms.ToolBarButtonStyle.Separator;
      this.tbbSeparator1.Visible = false;
      // 
      // tbbFirstPage
      // 
      this.tbbFirstPage.ImageIndex = 0;
      this.tbbFirstPage.Tag = "FirstPage";
      this.tbbFirstPage.Visible = false;
      // 
      // tbbPrevPage
      // 
      this.tbbPrevPage.Enabled = false;
      this.tbbPrevPage.ImageIndex = 1;
      this.tbbPrevPage.Tag = "PrevPage";
      this.tbbPrevPage.Visible = false;
      // 
      // tbbNextPage
      // 
      this.tbbNextPage.Enabled = false;
      this.tbbNextPage.ImageIndex = 2;
      this.tbbNextPage.Tag = "NextPage";
      this.tbbNextPage.Visible = false;
      // 
      // tbbLastPage
      // 
      this.tbbLastPage.Enabled = false;
      this.tbbLastPage.ImageIndex = 3;
      this.tbbLastPage.Tag = "LastPage";
      this.tbbLastPage.Visible = false;
      // 
      // tbbSeparator2
      // 
      this.tbbSeparator2.Style = System.Windows.Forms.ToolBarButtonStyle.Separator;
      this.tbbSeparator2.Visible = false;
      // 
      // tbbOriginalSize
      // 
      this.tbbOriginalSize.DropDownMenu = this.menuZoom;
      this.tbbOriginalSize.ImageIndex = 4;
      this.tbbOriginalSize.Style = System.Windows.Forms.ToolBarButtonStyle.DropDownButton;
      this.tbbOriginalSize.Tag = "OriginalSize";
      this.tbbOriginalSize.Text = "Original Size";
      // 
      // menuZoom
      // 
      this.menuZoom.MenuItems.AddRange(new System.Windows.Forms.MenuItem[] {
                                                                             this.miPercent800,
                                                                             this.miPercent600,
                                                                             this.miPercent400,
                                                                             this.miPercent200,
                                                                             this.miPercent150,
                                                                             this.miPercent100,
                                                                             this.miPercent75,
                                                                             this.miPercent50,
                                                                             this.miPercent25,
                                                                             this.miPercent10,
                                                                             this.menuItem10,
                                                                             this.miOriginalSize,
                                                                             this.miBestFit,
                                                                             this.miFullPage});
      // 
      // miPercent800
      // 
      this.miPercent800.Index = 0;
      this.miPercent800.Text = "800%";
      this.miPercent800.Click += new System.EventHandler(this.miPercent800_Click);
      // 
      // miPercent600
      // 
      this.miPercent600.Index = 1;
      this.miPercent600.Text = "600%";
      this.miPercent600.Click += new System.EventHandler(this.miPercent600_Click);
      // 
      // miPercent400
      // 
      this.miPercent400.Index = 2;
      this.miPercent400.Text = "400%";
      this.miPercent400.Click += new System.EventHandler(this.miPercent400_Click);
      // 
      // miPercent200
      // 
      this.miPercent200.Index = 3;
      this.miPercent200.Text = "200%";
      this.miPercent200.Click += new System.EventHandler(this.miPercent200_Click);
      // 
      // miPercent150
      // 
      this.miPercent150.Index = 4;
      this.miPercent150.Text = "150%";
      this.miPercent150.Click += new System.EventHandler(this.miPercent150_Click);
      // 
      // miPercent100
      // 
      this.miPercent100.Index = 5;
      this.miPercent100.Text = "100%";
      this.miPercent100.Click += new System.EventHandler(this.miPercent100_Click);
      // 
      // miPercent75
      // 
      this.miPercent75.Index = 6;
      this.miPercent75.Text = "75%";
      this.miPercent75.Click += new System.EventHandler(this.miPercent75_Click);
      // 
      // miPercent50
      // 
      this.miPercent50.Index = 7;
      this.miPercent50.Text = "50%";
      this.miPercent50.Click += new System.EventHandler(this.miPercent50_Click);
      // 
      // miPercent25
      // 
      this.miPercent25.Index = 8;
      this.miPercent25.Text = "25%";
      this.miPercent25.Click += new System.EventHandler(this.miPercent25_Click);
      // 
      // miPercent10
      // 
      this.miPercent10.Index = 9;
      this.miPercent10.Text = "10%";
      this.miPercent10.Click += new System.EventHandler(this.miPercent10_Click);
      // 
      // menuItem10
      // 
      this.menuItem10.Index = 10;
      this.menuItem10.Text = "-";
      // 
      // miOriginalSize
      // 
      this.miOriginalSize.Index = 11;
      this.miOriginalSize.Text = "Original Size";
      this.miOriginalSize.Click += new System.EventHandler(this.miOriginalSize_Click);
      // 
      // miBestFit
      // 
      this.miBestFit.Index = 12;
      this.miBestFit.Text = "Best fit";
      this.miBestFit.Click += new System.EventHandler(this.miBestFit_Click);
      // 
      // miFullPage
      // 
      this.miFullPage.Index = 13;
      this.miFullPage.Text = "Full Page";
      this.miFullPage.Click += new System.EventHandler(this.miFullPage_Click);
      // 
      // tbbFullPage
      // 
      this.tbbFullPage.ImageIndex = 5;
      this.tbbFullPage.Tag = "FullPage";
      this.tbbFullPage.Text = "Full Page";
      // 
      // tbbBestFit
      // 
      this.tbbBestFit.ImageIndex = 6;
      this.tbbBestFit.Tag = "BestFit";
      this.tbbBestFit.Text = "Best Fit";
      // 
      // tbbSmaller
      // 
      this.tbbSmaller.ImageIndex = 7;
      this.tbbSmaller.Tag = "Smaller";
      this.tbbSmaller.Text = "Smaller";
      // 
      // tbbLarger
      // 
      this.tbbLarger.ImageIndex = 8;
      this.tbbLarger.Tag = "Larger";
      this.tbbLarger.Text = "Larger";
      // 
      // tbbSeparator3
      // 
      this.tbbSeparator3.Style = System.Windows.Forms.ToolBarButtonStyle.Separator;
      // 
      // tbbMakePdf
      // 
      this.tbbMakePdf.ImageIndex = 9;
      this.tbbMakePdf.Tag = "MakePdf";
      this.tbbMakePdf.Text = "Create PDF";
      // 
      // ilToolbar
      // 
      this.ilToolbar.ImageSize = new System.Drawing.Size(16, 16);
      this.ilToolbar.ImageStream = ((System.Windows.Forms.ImageListStreamer)(resources.GetObject("ilToolbar.ImageStream")));
      this.ilToolbar.TransparentColor = System.Drawing.Color.Lime;
      // 
      // statusBar
      // 
      this.statusBar.Location = new System.Drawing.Point(0, 454);
      this.statusBar.Name = "statusBar";
      this.statusBar.Size = new System.Drawing.Size(638, 22);
      this.statusBar.SizingGrip = false;
      this.statusBar.TabIndex = 2;
      // 
      // pagePreview
      // 
      this.pagePreview.BackColor = System.Drawing.SystemColors.Control;
      this.pagePreview.BorderStyle = System.Windows.Forms.BorderStyle.Fixed3D;
      this.pagePreview.DesktopColor = System.Drawing.SystemColors.ControlDark;
      this.pagePreview.Dock = System.Windows.Forms.DockStyle.Fill;
      this.pagePreview.Location = new System.Drawing.Point(0, 42);
      this.pagePreview.Name = "pagePreview";
      this.pagePreview.PageColor = System.Drawing.Color.GhostWhite;
      this.pagePreview.PageSize = new System.Drawing.Size(595, 842);
      this.pagePreview.Size = new System.Drawing.Size(638, 412);
      this.pagePreview.TabIndex = 4;
      this.pagePreview.Zoom = PdfSharp.Forms.Zoom.FullPage;
      this.pagePreview.ZoomPercent = 34;
      // 
      // PreviewForm
      // 
      this.AutoScaleBaseSize = new System.Drawing.Size(5, 13);
      this.ClientSize = new System.Drawing.Size(638, 476);
      this.Controls.Add(this.pagePreview);
      this.Controls.Add(this.statusBar);
      this.Controls.Add(this.toolBar);
      this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
      this.MaximizeBox = false;
      this.MinimizeBox = false;
      this.Name = "PreviewForm";
      this.ShowInTaskbar = false;
      this.SizeGripStyle = System.Windows.Forms.SizeGripStyle.Show;
      this.Text = "Preview";
      this.ResumeLayout(false);

    }
    #endregion

    protected override void OnClosing(CancelEventArgs e)
    {
      this.Hide();
    }

    protected override void OnSizeChanged(EventArgs e)
    {
      base.OnSizeChanged(e);
      UpdateStatusBar();
    }


    private void toolBar_ButtonClick(object sender, System.Windows.Forms.ToolBarButtonClickEventArgs e)
    {
      object tag = e.Button.Tag;
      if (tag != null)
      {
        switch (tag.ToString())
        {
          case "OriginalSize":
            this.pagePreview.Zoom = Zoom.OriginalSize;
            break;

          case "FullPage":
            this.pagePreview.Zoom = Zoom.FullPage;
            break;

          case "BestFit":
            this.pagePreview.Zoom = Zoom.BestFit;
            break;

          case "Smaller":
            this.pagePreview.ZoomPercent = GetNewZoom((int)this.pagePreview.ZoomPercent, false);
            break;

          case "Larger":
            this.pagePreview.ZoomPercent = GetNewZoom((int)this.pagePreview.ZoomPercent, true);
            break;

          case "MakePdf":
            MakePdf();
            break;
        }
        UpdateStatusBar();
      }
    }

    private void miPercent800_Click(object sender, System.EventArgs e)
    {
      this.pagePreview.Zoom = Zoom.Percent800;
      UpdateStatusBar();
    }

    private void miPercent600_Click(object sender, System.EventArgs e)
    {
      this.pagePreview.Zoom = Zoom.Percent600;
      UpdateStatusBar();
    }

    private void miPercent400_Click(object sender, System.EventArgs e)
    {
      this.pagePreview.Zoom = Zoom.Percent400;
      UpdateStatusBar();
    }

    private void miPercent200_Click(object sender, System.EventArgs e)
    {
      this.pagePreview.Zoom = Zoom.Percent200;
      UpdateStatusBar();
    }

    private void miPercent100_Click(object sender, System.EventArgs e)
    {
      this.pagePreview.Zoom = Zoom.Percent100;
      UpdateStatusBar();
    }

    private void miPercent150_Click(object sender, System.EventArgs e)
    {
      this.pagePreview.Zoom = Zoom.Percent150;
      UpdateStatusBar();
    }

    private void miPercent75_Click(object sender, System.EventArgs e)
    {
      this.pagePreview.Zoom = Zoom.Percent75;
      UpdateStatusBar();
    }

    private void miPercent50_Click(object sender, System.EventArgs e)
    {
      this.pagePreview.Zoom = Zoom.Percent50;
      UpdateStatusBar();
    }

    private void miPercent25_Click(object sender, System.EventArgs e)
    {
      this.pagePreview.Zoom = Zoom.Percent25;
      UpdateStatusBar();
    }

    private void miPercent10_Click(object sender, System.EventArgs e)
    {
      this.pagePreview.Zoom = Zoom.Percent10;
      UpdateStatusBar();
    }

    private void miOriginalSize_Click(object sender, EventArgs e)
    {
      this.pagePreview.Zoom = Zoom.OriginalSize;
      UpdateStatusBar();
    }

    private void miBestFit_Click(object sender, System.EventArgs e)
    {
      this.pagePreview.Zoom = Zoom.BestFit;
      UpdateStatusBar();
    }

    private void miFullPage_Click(object sender, System.EventArgs e)
    {
      this.pagePreview.Zoom = Zoom.FullPage;
      UpdateStatusBar();
    }

  }
}
